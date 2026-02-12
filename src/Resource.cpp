#include "Resource.h"

#include "ResourceData.h"
#include "Reticulum.h"
#include "Transport.h"
#include "Identity.h"
#include "Packet.h"
#include "Log.h"
#include "Utilities/OS.h"

#include <ArduinoJson.h>
#include <algorithm>
#include <cmath>

#ifdef RET_BZ2_SUPPORT
#include "bz2/bzlib.h"
#endif

using namespace RNS;
using namespace RNS::Utilities;

// Max resource size we'll accept (safety valve for embedded)
static const size_t MAX_ACCEPT_SIZE = 64 * 1024;

#ifdef RET_BZ2_SUPPORT
// Max decompressed output size (safety valve)
static const size_t MAX_DECOMPRESS_SIZE = 256 * 1024;

static Bytes bz2_decompress(const Bytes& compressed, size_t expected_size) {
	if (expected_size > MAX_DECOMPRESS_SIZE) {
		ERRORF("bz2 output %zu exceeds cap %zu", expected_size, MAX_DECOMPRESS_SIZE);
		return {Bytes::NONE};
	}
	unsigned int dest_len = (unsigned int)(expected_size + 1024);
	uint8_t* dest = (uint8_t*)malloc(dest_len);
	if (!dest) { ERROR("bz2 alloc failed"); return {Bytes::NONE}; }

	int ret = BZ2_bzBuffToBuffDecompress(
		(char*)dest, &dest_len,
		(char*)compressed.data(), (unsigned int)compressed.size(),
		0, 0);  // small=0, verbosity=0

	if (ret != BZ_OK) {
		ERRORF("bz2 decompress error %d", ret);
		free(dest); return {Bytes::NONE};
	}
	Bytes result(dest, (size_t)dest_len);
	free(dest);
	return result;
}
#endif

//Resource::Resource(const Link& link /*= {Type::NONE}*/) :
//	_object(new ResourceData(link))
//{
//	assert(_object);
//	MEM("Resource object created");
//}

Resource::Resource(const Bytes& data, const Link& link, const Bytes& request_id, bool is_response, double timeout) :
	_object(new ResourceData(link))
{
	assert(_object);
	MEM("Resource object created");
}

Resource::Resource(const Bytes& data, const Link& link, bool do_advertise /*= true*/, bool auto_compress /*= true*/, Callbacks::concluded callback /*= nullptr*/, Callbacks::progress progress_callback /*= nullptr*/, double timeout /*= 0.0*/, int segment_index /*= 1*/, const Bytes& original_hash /*= {Type::NONE}*/, const Bytes& request_id /*= {Type::NONE}*/, bool is_response /*= false*/) :
	_object(new ResourceData(link))
{
	assert(_object);
	MEM("Resource object created");

	if (!data || data.size() == 0) {
		ERROR("Cannot create send-side resource with empty data");
		return;
	}

	_object->_data = data;
	_object->_size = data.size();
	_object->_total_size = data.size();
	_object->_initiator = true;
	_object->_callbacks._concluded = callback;
	_object->_callbacks._progress = progress_callback;
	_object->_encrypted = true;  // Always encrypted over links
	_object->_compressed = false; // No compression support
	_object->_split = false;
	_object->_segment_index = (uint8_t)segment_index;
	_object->_total_segments = 1;
	_object->_sdu = Type::Resource::SDU;
	_object->_last_activity = OS::time();
	_object->_retries_left = Type::Resource::MAX_RETRIES;

	if (request_id) {
		_object->_request_id = request_id;
	}

	// Generate random hash (4 bytes) and check for hashmap collisions
	bool collision = true;
	while (collision) {
		_object->_random_hash = Identity::get_random_hash().left(Type::Resource::RANDOM_HASH_SIZE);

		// Compute resource hash: SHA256(original_data + random_hash)
		Bytes hash_input(data.size() + Type::Resource::RANDOM_HASH_SIZE);
		hash_input.append(data);
		hash_input.append(_object->_random_hash);
		_object->_hash = Identity::full_hash(hash_input);

		if (original_hash) {
			_object->_original_hash = original_hash;
		} else {
			_object->_original_hash = _object->_hash;
		}

		// Compute expected proof: SHA256(original_data + resource_hash)
		Bytes proof_input(data.size() + Type::Identity::HASHLENGTH / 8);
		proof_input.append(data);
		proof_input.append(_object->_hash);
		_object->_expected_proof = Identity::full_hash(proof_input);

		// Prepare transfer data: nonce + original data
		Bytes transfer_data(Type::Resource::RANDOM_HASH_SIZE + data.size());
		transfer_data.append(_object->_random_hash);
		transfer_data.append(data);

		// Encrypt
		Bytes encrypted = link.encrypt(transfer_data);
		_object->_size = encrypted.size();

		// Split into SDU-sized parts
		uint16_t est_parts = (uint16_t)std::ceil((float)encrypted.size() / (float)_object->_sdu);
		_object->_sent_parts.clear();
		_object->_sent_parts.reserve(est_parts);
		size_t offset = 0;
		while (offset < encrypted.size()) {
			size_t chunk = std::min((size_t)_object->_sdu, encrypted.size() - offset);
			_object->_sent_parts.push_back(encrypted.mid(offset, chunk));
			offset += chunk;
		}
		_object->_total_parts = (uint16_t)_object->_sent_parts.size();

		// Build hashmap and check for collisions using linear scan
		// (avoids std::set tree overhead; part counts are small on embedded)
		_object->_hashmap.clear();
		_object->_hashmap.reserve(_object->_total_parts);
		collision = false;
		for (uint16_t i = 0; i < _object->_total_parts; i++) {
			Bytes mh = get_map_hash(_object->_sent_parts[i]);
			// Linear scan for collision — O(n^2) but n is tiny (typ < 150 parts)
			for (uint16_t j = 0; j < i; j++) {
				if (_object->_hashmap[j] == mh) {
					collision = true;
					TRACE("Hashmap collision detected, regenerating random hash");
					break;
				}
			}
			if (collision) break;
			_object->_hashmap.push_back(mh);
		}
	}

	// Build flags byte
	_object->_flags = 0;
	if (_object->_encrypted) _object->_flags |= 0x01;
	if (_object->_compressed) _object->_flags |= 0x02;
	if (_object->_split) _object->_flags |= 0x04;
	if (request_id && !is_response) _object->_flags |= 0x08; // is_request
	if (is_response) _object->_flags |= 0x10;

	_object->_status = Type::Resource::QUEUED;
	_object->_sent_count = 0;

	DEBUGF("Resource %s created for sending, %zu bytes in %u parts",
		_object->_hash.toHex().c_str(), _object->_total_size, _object->_total_parts);

	// Release original data — send-side only needs _sent_parts, _hashmap,
	// _hash, and _expected_proof (all already computed). Saves significant
	// RAM on memory-constrained ESP32.
	_object->_data.clear();

	if (do_advertise) {
		advertise();
	}
}


/*static*/ Resource Resource::accept(const Packet& advertisement_packet, Callbacks::concluded callback /*= nullptr*/, Callbacks::progress progress_callback /*= nullptr*/, const Bytes& request_id /*= {Type::NONE}*/) {
	try {
		ResourceAdvertisement adv = ResourceAdvertisement::unpack(const_cast<Packet&>(advertisement_packet).plaintext());

		if (adv.c) {
#ifndef RET_BZ2_SUPPORT
			ERROR("Resource is compressed (bz2), compile with RET_BZ2_SUPPORT to enable");
			return {Type::NONE};
#endif
		}

		if (adv.t == 0 || adv.n == 0) {
			ERROR("Resource advertisement has 0 transfer size or 0 parts, rejecting");
			return {Type::NONE};
		}

		if (adv.t > MAX_ACCEPT_SIZE) {
			ERRORF("Resource too large: %zu bytes, max %zu", adv.t, MAX_ACCEPT_SIZE);
			return {Type::NONE};
		}

		Link link = const_cast<Packet&>(advertisement_packet).link();
		Resource resource({Bytes::NONE}, link, request_id, false, 0.0);

		resource._object->_status = Type::Resource::TRANSFERRING;
		resource._object->_flags = adv.f;
		resource._object->_size = adv.t;
		resource._object->_total_size = adv.d;
		resource._object->_hash = adv.h;
		resource._object->_original_hash = adv.o;
		resource._object->_random_hash = adv.r;
		resource._object->_encrypted = adv.e;
		resource._object->_compressed = adv.c;
		resource._object->_split = adv.s;
		resource._object->_initiator = false;
		resource._object->_callbacks._concluded = callback;
		resource._object->_callbacks._progress = progress_callback;

		resource._object->_sdu = Type::Resource::SDU;
		resource._object->_total_parts = (uint16_t)std::ceil((float)resource._object->_size / (float)resource._object->_sdu);
		resource._object->_received_count = 0;
		resource._object->_outstanding_parts = 0;
		resource._object->_parts.resize(resource._object->_total_parts);
		resource._object->_window = Type::Resource::WINDOW;
		resource._object->_window_max = Type::Resource::WINDOW_MAX_SLOW;
		resource._object->_window_min = Type::Resource::WINDOW_MIN;
		resource._object->_last_activity = OS::time();
		resource._object->_retries_left = Type::Resource::MAX_RETRIES;
		resource._object->_segment_index = adv.i;
		resource._object->_total_segments = adv.l;

		if (request_id) {
			resource._object->_request_id = request_id;
		} else {
			resource._object->_request_id = adv.q;
		}

		// Initialize hashmap: one entry per part, all empty initially
		resource._object->_hashmap.resize(resource._object->_total_parts);
		resource._object->_hashmap_height = 0;
		resource._object->_waiting_for_hmu = false;
		resource._object->_consecutive_completed_height = -1;

		if (!link.has_incoming_resource(resource)) {
			link.register_incoming_resource(resource);

			DEBUGF("Accepting resource advertisement for %s. Transfer size is %zu in %u parts.",
				resource._object->_hash.toHex().c_str(),
				resource._object->_size,
				resource._object->_total_parts);

			// Fire resource_started callback
			Link::Callbacks::resource_started started_cb = link.callbacks_resource_started();
			if (started_cb) {
				try {
					started_cb(resource);
				} catch (std::exception& e) {
					ERRORF("Error executing resource started callback: %s", e.what());
				}
			}

			// Process initial hashmap from advertisement
			resource.hashmap_update(0, adv.m);
			return resource;
		} else {
			DEBUGF("Ignoring resource advertisement for %s, resource already transferring",
				resource._object->_hash.toHex().c_str());
			return {Type::NONE};
		}
	} catch (std::exception& e) {
		ERRORF("Could not decode resource advertisement, dropping resource: %s", e.what());
		return {Type::NONE};
	}
}


Bytes Resource::get_map_hash(const Bytes& part_data) const {
	assert(_object);
	Bytes hash_input;
	hash_input.append(part_data);
	hash_input.append(_object->_random_hash);
	return Identity::full_hash(hash_input).left(Type::Resource::MAPHASH_LEN);
}

void Resource::hashmap_update(uint16_t segment, const Bytes& hashmap_data) {
	assert(_object);
	if (_object->_status == Type::Resource::FAILED) return;

	_object->_status = Type::Resource::TRANSFERRING;
	uint16_t seg_len = Type::Resource::ResourceAdvertisement::HASHMAP_MAX_LEN;
	uint16_t hashes = hashmap_data.size() / Type::Resource::MAPHASH_LEN;

	for (uint16_t i = 0; i < hashes; i++) {
		uint16_t idx = i + segment * seg_len;
		if (idx >= _object->_total_parts) break;

		if (!_object->_hashmap[idx]) {
			_object->_hashmap_height++;
		}
		_object->_hashmap[idx] = hashmap_data.mid(i * Type::Resource::MAPHASH_LEN, Type::Resource::MAPHASH_LEN);
	}

	_object->_waiting_for_hmu = false;
	request_next();
}

void Resource::hashmap_update_packet(const Bytes& plaintext) {
	assert(_object);
	if (_object->_status == Type::Resource::FAILED) return;

	_object->_last_activity = OS::time();
	_object->_retries_left = Type::Resource::MAX_RETRIES;

	// Plaintext format: [resource_hash (32 bytes)][msgpack([segment_index, hashmap_bytes])]
	size_t hash_len = Type::Identity::HASHLENGTH / 8;
	if (plaintext.size() <= hash_len) return;

	Bytes packed = plaintext.mid(hash_len);

	JsonDocument doc;
	DeserializationError error = deserializeMsgPack(doc, packed.data(), packed.size());
	if (error) {
		ERRORF("Failed to decode hashmap update: %s", error.c_str());
		return;
	}

	if (!doc.is<JsonArray>() || doc.size() < 2) return;

	uint16_t segment = doc[0].as<uint16_t>();

	MsgPackBinary bin = doc[1].as<MsgPackBinary>();
	if (bin.data() && bin.size() > 0) {
		Bytes hm_bytes((const uint8_t*)bin.data(), bin.size());
		hashmap_update(segment, hm_bytes);
	}
}

void Resource::receive_part(const Packet& packet) {
	assert(_object);

	_object->_last_activity = OS::time();
	_object->_retries_left = Type::Resource::MAX_RETRIES;

	if (_object->_status == Type::Resource::FAILED) return;

	_object->_status = Type::Resource::TRANSFERRING;
	Bytes part_data = packet.data();
	Bytes part_hash = get_map_hash(part_data);

	// Search within window from consecutive completed height
	int32_t consecutive_index = _object->_consecutive_completed_height >= 0 ?
		_object->_consecutive_completed_height : 0;

	for (int32_t i = consecutive_index;
		 i < consecutive_index + _object->_window && i < _object->_total_parts;
		 i++) {
		if (_object->_hashmap[i] && _object->_hashmap[i] == part_hash) {
			if (!_object->_parts[i]) {
				_object->_parts[i] = part_data;
				_object->_received_count++;
				if (_object->_outstanding_parts > 0) {
					_object->_outstanding_parts--;
				}

				// Update consecutive completed pointer
				if (i == _object->_consecutive_completed_height + 1) {
					_object->_consecutive_completed_height = i;
				}

				int32_t cp = _object->_consecutive_completed_height + 1;
				while (cp < _object->_total_parts && _object->_parts[cp]) {
					_object->_consecutive_completed_height = cp;
					cp++;
				}

				if (_object->_callbacks._progress) {
					try {
						_object->_callbacks._progress(*this);
					} catch (std::exception& e) {
						ERRORF("Error executing progress callback: %s", e.what());
					}
				}
			}
			break;
		}
	}

	if (_object->_received_count == _object->_total_parts) {
		assemble();
	} else if (_object->_outstanding_parts == 0) {
		// Window expansion
		if (_object->_window < _object->_window_max) {
			_object->_window++;
		}
		request_next();
	}
}

void Resource::request_next() {
	assert(_object);
	if (_object->_status == Type::Resource::FAILED) return;
	if (_object->_waiting_for_hmu) return;

	_object->_outstanding_parts = 0;
	uint8_t hashmap_exhausted = Type::Resource::HASHMAP_IS_NOT_EXHAUSTED;
	Bytes requested_hashes;

	uint16_t pn = (uint16_t)(_object->_consecutive_completed_height + 1);
	uint16_t search_start = pn;
	uint16_t i = 0;

	for (uint16_t idx = search_start;
		 idx < search_start + _object->_window && idx < _object->_total_parts;
		 idx++) {
		if (!_object->_parts[idx]) {
			if (_object->_hashmap[idx]) {
				requested_hashes.append(_object->_hashmap[idx]);
				_object->_outstanding_parts++;
				i++;
			} else {
				hashmap_exhausted = Type::Resource::HASHMAP_IS_EXHAUSTED;
			}
		}

		if (i >= _object->_window || hashmap_exhausted == Type::Resource::HASHMAP_IS_EXHAUSTED) {
			break;
		}
	}

	Bytes hmu_part;
	hmu_part.append(hashmap_exhausted);
	if (hashmap_exhausted == Type::Resource::HASHMAP_IS_EXHAUSTED) {
		if (_object->_hashmap_height > 0) {
			hmu_part.append(_object->_hashmap[_object->_hashmap_height - 1]);
		}
		_object->_waiting_for_hmu = true;
	}

	Bytes request_data;
	request_data.append(hmu_part);
	request_data.append(_object->_hash);
	request_data.append(requested_hashes);

	try {
		Packet request_packet(_object->_link, request_data, Type::Packet::DATA, Type::Packet::RESOURCE_REQ);
		request_packet.send();
		_object->_last_activity = OS::time();
		TRACEF("Resource %s: sent request for %u parts", _object->_hash.toHex().c_str(), _object->_outstanding_parts);
	} catch (std::exception& e) {
		ERRORF("Could not send resource request packet, cancelling resource: %s", e.what());
		cancel();
	}
}

void Resource::assemble() {
	assert(_object);
	if (_object->_status == Type::Resource::FAILED) return;

	try {
		_object->_status = Type::Resource::ASSEMBLING;

		// Concatenate all parts
		Bytes stream;
		for (uint16_t i = 0; i < _object->_total_parts; i++) {
			stream.append(_object->_parts[i]);
		}

		// Decrypt if encrypted
		Bytes decrypted;
		if (_object->_encrypted) {
			decrypted = _object->_link.decrypt(stream);
		} else {
			decrypted = stream;
		}

		// Strip random hash nonce (first RANDOM_HASH_SIZE bytes)
		if (decrypted.size() <= Type::Resource::RANDOM_HASH_SIZE) {
			ERROR("Resource data too small after decryption");
			_object->_status = Type::Resource::CORRUPT;
			_object->_link.resource_concluded(*this);
			return;
		}
		Bytes data = decrypted.mid(Type::Resource::RANDOM_HASH_SIZE);

		// Decompress if compressed
		if (_object->_compressed) {
#ifdef RET_BZ2_SUPPORT
			Bytes decompressed = bz2_decompress(data, _object->_total_size);
			if (!decompressed) {
				_object->_status = Type::Resource::CORRUPT;
				_object->_link.resource_concluded(*this);
				return;
			}
			data = decompressed;
#else
			ERROR("bz2 decompression not supported (compile with RET_BZ2_SUPPORT)");
			_object->_status = Type::Resource::CORRUPT;
			_object->_link.resource_concluded(*this);
			return;
#endif
		}

		_object->_data = data;

		// Verify hash: SHA256(data + random_hash) must equal resource hash
		Bytes hash_input;
		hash_input.append(_object->_data);
		hash_input.append(_object->_random_hash);
		Bytes calculated_hash = Identity::full_hash(hash_input);

		if (calculated_hash == _object->_hash) {
			_object->_status = Type::Resource::COMPLETE;
			DEBUGF("Resource %s assembled successfully, %zu bytes",
				_object->_hash.toHex().c_str(), _object->_data.size());
			prove();
		} else {
			ERROR("Resource hash verification failed");
			_object->_status = Type::Resource::CORRUPT;
		}

		// Free parts memory
		_object->_parts.clear();
		_object->_hashmap.clear();

	} catch (std::exception& e) {
		ERRORF("Error while assembling resource: %s", e.what());
		_object->_status = Type::Resource::CORRUPT;
	}

	_object->_link.resource_concluded(*this);

	if (_object->_callbacks._concluded) {
		try {
			_object->_callbacks._concluded(*this);
		} catch (std::exception& e) {
			ERRORF("Error executing resource concluded callback: %s", e.what());
		}
	}
}

void Resource::prove() {
	assert(_object);
	if (_object->_status == Type::Resource::FAILED) return;

	try {
		// proof = SHA256(data + hash)
		Bytes proof_input;
		proof_input.append(_object->_data);
		proof_input.append(_object->_hash);
		Bytes proof = Identity::full_hash(proof_input);

		// proof packet data = resource_hash + proof
		Bytes proof_data;
		proof_data.append(_object->_hash);
		proof_data.append(proof);

		Packet proof_packet(_object->_link, proof_data, Type::Packet::PROOF, Type::Packet::RESOURCE_PRF);
		proof_packet.send();
		TRACEF("Resource %s: proof sent", _object->_hash.toHex().c_str());
	} catch (std::exception& e) {
		ERRORF("Could not send proof packet, cancelling resource: %s", e.what());
		cancel();
	}
}

void Resource::advertise() {
	assert(_object);

	ResourceAdvertisement adv;
	adv.t = _object->_size;
	adv.d = _object->_total_size;
	adv.n = _object->_total_parts;
	adv.h = _object->_hash;
	adv.r = _object->_random_hash;
	adv.o = _object->_original_hash;
	adv.f = _object->_flags;
	adv.i = _object->_segment_index;
	adv.l = _object->_total_segments;
	adv.q = _object->_request_id;

	// Include first HASHMAP_MAX_LEN entries of hashmap
	uint16_t hm_count = std::min((uint16_t)_object->_hashmap.size(),
		(uint16_t)Type::Resource::ResourceAdvertisement::HASHMAP_MAX_LEN);
	Bytes hm_bytes(hm_count * Type::Resource::MAPHASH_LEN);
	for (uint16_t i = 0; i < hm_count; i++) {
		hm_bytes.append(_object->_hashmap[i]);
	}
	adv.m = hm_bytes;

	try {
		Bytes packed = ResourceAdvertisement::pack(adv);
		Packet adv_packet(_object->_link, packed, Type::Packet::DATA, Type::Packet::RESOURCE_ADV);
		adv_packet.send();
		_object->_status = Type::Resource::ADVERTISED;
		_object->_last_activity = OS::time();
		_object->_link.register_outgoing_resource(*this);
		DEBUGF("Resource %s: advertisement sent", _object->_hash.toHex().c_str());
	} catch (std::exception& e) {
		ERRORF("Could not send resource advertisement: %s", e.what());
		_object->_status = Type::Resource::FAILED;
	}
}

void Resource::request(const Bytes& request_data) {
	assert(_object);
	if (_object->_status == Type::Resource::FAILED) return;

	_object->_last_activity = OS::time();
	_object->_retries_left = Type::Resource::MAX_RETRIES;

	if (request_data.size() < 1) return;

	// Parse exhaustion flag
	bool exhausted = request_data.data()[0] == Type::Resource::HASHMAP_IS_EXHAUSTED;
	size_t offset = 1;

	if (exhausted) {
		// Extract last map hash and determine segment
		if (request_data.size() < 1 + Type::Resource::MAPHASH_LEN) return;
		Bytes last_map_hash = request_data.mid(1, Type::Resource::MAPHASH_LEN);
		offset += Type::Resource::MAPHASH_LEN;

		// Find which segment boundary this corresponds to
		uint16_t seg_len = Type::Resource::ResourceAdvertisement::HASHMAP_MAX_LEN;
		uint16_t segment = 0;
		for (uint16_t i = 0; i < _object->_hashmap.size(); i++) {
			if (_object->_hashmap[i] == last_map_hash) {
				segment = (uint16_t)((i + 1) / seg_len);
				break;
			}
		}
		send_hashmap_update(segment);
	}

	// Skip resource hash (32 bytes)
	size_t hash_len = Type::Identity::HASHLENGTH / 8;
	if (request_data.size() < offset + hash_len) return;
	offset += hash_len;

	// Extract requested part hashes and send matching parts
	_object->_status = Type::Resource::TRANSFERRING;
	while (offset + Type::Resource::MAPHASH_LEN <= request_data.size()) {
		Bytes requested_hash = request_data.mid(offset, Type::Resource::MAPHASH_LEN);
		offset += Type::Resource::MAPHASH_LEN;

		for (uint16_t i = 0; i < _object->_total_parts; i++) {
			if (_object->_hashmap[i] == requested_hash) {
				try {
					Packet part_packet(_object->_link, _object->_sent_parts[i], Type::Packet::DATA, Type::Packet::RESOURCE);
					part_packet.send();
					_object->_sent_count++;
				} catch (std::exception& e) {
					ERRORF("Could not send resource part: %s", e.what());
					cancel();
					return;
				}
				break;
			}
		}
	}

	TRACEF("Resource %s: sent %u parts total", _object->_hash.toHex().c_str(), _object->_sent_count);
}

void Resource::send_hashmap_update(uint16_t segment) {
	assert(_object);

	uint16_t seg_len = Type::Resource::ResourceAdvertisement::HASHMAP_MAX_LEN;
	uint16_t start = segment * seg_len;
	uint16_t end = std::min((uint16_t)(start + seg_len), _object->_total_parts);

	Bytes hm_bytes((end - start) * Type::Resource::MAPHASH_LEN);
	for (uint16_t i = start; i < end; i++) {
		hm_bytes.append(_object->_hashmap[i]);
	}

	// Pack as msgpack array: [segment, hashmap_bytes]
	JsonDocument doc;
	doc.add(segment);
	doc.add(MsgPackBinary(hm_bytes.data(), hm_bytes.size()));

	uint8_t packed_buf[512];
	size_t packed_len = serializeMsgPack(doc, packed_buf, sizeof(packed_buf));

	// HMU data: resource_hash + packed
	Bytes hmu_data;
	hmu_data.append(_object->_hash);
	hmu_data.append(Bytes(packed_buf, packed_len));

	try {
		Packet hmu_packet(_object->_link, hmu_data, Type::Packet::DATA, Type::Packet::RESOURCE_HMU);
		hmu_packet.send();
		TRACEF("Resource %s: sent HMU for segment %u", _object->_hash.toHex().c_str(), segment);
	} catch (std::exception& e) {
		ERRORF("Could not send hashmap update: %s", e.what());
	}
}

void Resource::validate_proof(const Bytes& proof_data) {
	assert(_object);
	if (_object->_status == Type::Resource::FAILED) return;

	size_t hash_len = Type::Identity::HASHLENGTH / 8;
	if (proof_data.size() < hash_len * 2) {
		ERROR("Proof data too short");
		cancel();
		return;
	}

	Bytes received_hash = proof_data.left(hash_len);
	Bytes received_proof = proof_data.mid(hash_len);

	if (received_hash != _object->_hash) {
		ERROR("Proof resource hash mismatch");
		cancel();
		return;
	}

	if (received_proof == _object->_expected_proof) {
		_object->_status = Type::Resource::COMPLETE;
		DEBUGF("Resource %s: proof validated, transfer complete", _object->_hash.toHex().c_str());

		// Free send-side data now that transfer is complete
		_object->_sent_parts.clear();
		_object->_hashmap.clear();

		_object->_link.resource_concluded(*this);

		if (_object->_callbacks._concluded) {
			try {
				_object->_callbacks._concluded(*this);
			} catch (std::exception& e) {
				ERRORF("Error executing resource concluded callback: %s", e.what());
			}
		}
	} else {
		ERROR("Resource proof validation failed");
		cancel();
	}
}

void Resource::cancel() {
	assert(_object);
	_object->_status = Type::Resource::FAILED;
	_object->_parts.clear();
	_object->_hashmap.clear();
	_object->_sent_parts.clear();
	_object->_link.resource_concluded(*this);

	if (_object->_callbacks._concluded) {
		try {
			_object->_callbacks._concluded(*this);
		} catch (std::exception& e) {
			ERRORF("Error executing resource concluded callback: %s", e.what());
		}
	}
}

float Resource::get_progress() const {
	assert(_object);
	if (_object->_total_parts == 0) return 0.0f;
	return (float)_object->_received_count / (float)_object->_total_parts;
}

void Resource::set_concluded_callback(Callbacks::concluded callback) {
	assert(_object);
	_object->_callbacks._concluded = callback;
}

void Resource::set_progress_callback(Callbacks::progress callback) {
	assert(_object);
	_object->_callbacks._progress = callback;
}


std::string Resource::toString() const {
	if (!_object) {
		return "";
	}
	if (_object->_hash) {
		return "{Resource:" + _object->_hash.toHex() + "}";
	}
	return "{Resource: unknown}";
}

// getters
const Bytes& Resource::hash() const {
	assert(_object);
	return _object->_hash;
}

const Bytes& Resource::request_id() const {
	assert(_object);
	return _object->_request_id;
}

const Bytes& Resource::data() const {
	assert(_object);
	return _object->_data;
}

const Type::Resource::status Resource::status() const {
	assert(_object);
	return _object->_status;
}

const size_t Resource::size() const {
	assert(_object);
	return _object->_size;
}

const size_t Resource::total_size() const {
	assert(_object);
	return _object->_total_size;
}

const Link& Resource::link() const {
	assert(_object);
	return _object->_link;
}

bool Resource::initiator() const {
	assert(_object);
	return _object->_initiator;
}

// setters


// ---- ResourceAdvertisement ----

ResourceAdvertisement ResourceAdvertisement::unpack(const Bytes& data) {
	JsonDocument doc;
	DeserializationError error = deserializeMsgPack(doc, data.data(), data.size());
	if (error) {
		throw std::runtime_error(std::string("Failed to decode resource advertisement: ") + error.c_str());
	}

	ResourceAdvertisement adv;
	adv.t = doc["t"].as<size_t>();
	adv.d = doc["d"].as<size_t>();
	adv.n = doc["n"].as<uint16_t>();

	// Binary fields
	if (doc["h"].is<MsgPackBinary>()) {
		MsgPackBinary bin = doc["h"].as<MsgPackBinary>();
		adv.h = Bytes((const uint8_t*)bin.data(), bin.size());
	}
	if (doc["r"].is<MsgPackBinary>()) {
		MsgPackBinary bin = doc["r"].as<MsgPackBinary>();
		adv.r = Bytes((const uint8_t*)bin.data(), bin.size());
	}
	if (doc["o"].is<MsgPackBinary>()) {
		MsgPackBinary bin = doc["o"].as<MsgPackBinary>();
		adv.o = Bytes((const uint8_t*)bin.data(), bin.size());
	}
	if (doc["m"].is<MsgPackBinary>()) {
		MsgPackBinary bin = doc["m"].as<MsgPackBinary>();
		adv.m = Bytes((const uint8_t*)bin.data(), bin.size());
	}
	if (doc["q"].is<MsgPackBinary>()) {
		MsgPackBinary bin = doc["q"].as<MsgPackBinary>();
		adv.q = Bytes((const uint8_t*)bin.data(), bin.size());
	} else if (!doc["q"].isNull()) {
		// request_id might be null
		adv.q = Bytes();
	}

	adv.f = doc["f"].as<uint8_t>();
	adv.i = doc["i"].as<uint8_t>();
	adv.l = doc["l"].as<uint8_t>();

	// Decode flags
	adv.e = (adv.f & 0x01) != 0;
	adv.c = ((adv.f >> 1) & 0x01) != 0;
	adv.s = ((adv.f >> 2) & 0x01) != 0;
	adv.u = ((adv.f >> 3) & 0x01) != 0;
	adv.p = ((adv.f >> 4) & 0x01) != 0;
	adv.x = ((adv.f >> 5) & 0x01) != 0;

	return adv;
}

/*static*/ bool ResourceAdvertisement::is_request(const Packet& advertisement_packet) {
	try {
		ResourceAdvertisement adv = unpack(const_cast<Packet&>(advertisement_packet).plaintext());
		return adv.q && adv.u;
	} catch (...) {
		return false;
	}
}

/*static*/ bool ResourceAdvertisement::is_response(const Packet& advertisement_packet) {
	try {
		ResourceAdvertisement adv = unpack(const_cast<Packet&>(advertisement_packet).plaintext());
		return adv.q && adv.p;
	} catch (...) {
		return false;
	}
}

/*static*/ Bytes ResourceAdvertisement::read_request_id(const Packet& advertisement_packet) {
	try {
		ResourceAdvertisement adv = unpack(const_cast<Packet&>(advertisement_packet).plaintext());
		return adv.q;
	} catch (...) {
		return Bytes();
	}
}

/*static*/ size_t ResourceAdvertisement::read_transfer_size(const Packet& advertisement_packet) {
	try {
		ResourceAdvertisement adv = unpack(const_cast<Packet&>(advertisement_packet).plaintext());
		return adv.t;
	} catch (...) {
		return 0;
	}
}

/*static*/ Bytes ResourceAdvertisement::pack(const ResourceAdvertisement& adv) {
	JsonDocument doc;
	doc["t"] = adv.t;
	doc["d"] = adv.d;
	doc["n"] = adv.n;
	doc["h"] = MsgPackBinary(adv.h.data(), adv.h.size());
	doc["r"] = MsgPackBinary(adv.r.data(), adv.r.size());
	doc["o"] = MsgPackBinary(adv.o.data(), adv.o.size());
	doc["i"] = adv.i;
	doc["l"] = adv.l;
	if (adv.q) {
		doc["q"] = MsgPackBinary(adv.q.data(), adv.q.size());
	} else {
		doc["q"] = nullptr;
	}
	doc["f"] = adv.f;
	doc["m"] = MsgPackBinary(adv.m.data(), adv.m.size());

	uint8_t buffer[512];
	size_t len = serializeMsgPack(doc, buffer, sizeof(buffer));
	return Bytes(buffer, len);
}

/*static*/ size_t ResourceAdvertisement::read_size(const Packet& advertisement_packet) {
	try {
		ResourceAdvertisement adv = unpack(const_cast<Packet&>(advertisement_packet).plaintext());
		return adv.d;
	} catch (...) {
		return 0;
	}
}
