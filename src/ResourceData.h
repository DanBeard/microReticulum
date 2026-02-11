#pragma once

#include "Resource.h"

#include "Interface.h"
#include "Packet.h"
#include "Destination.h"
#include "Bytes.h"
#include "Type.h"
#include "Cryptography/Token.h"

#include <vector>

namespace RNS {

	class ResourceData {
	public:
		ResourceData(const Link& link) : _link(link) {}
		virtual ~ResourceData() {}
	private:
		Link _link;
		Bytes _hash;
		Bytes _request_id;
		Bytes _data;
		Type::Resource::status _status = Type::Resource::NONE;
		size_t _size = 0;
		size_t _total_size = 0;
		Resource::Callbacks _callbacks;

		// Receive-side state (populated by Resource::accept)
		bool _initiator = true;
		bool _encrypted = false;
		bool _compressed = false;
		bool _split = false;
		uint8_t _flags = 0;
		Bytes _random_hash;
		Bytes _original_hash;
		uint16_t _total_parts = 0;
		uint16_t _received_count = 0;
		uint16_t _outstanding_parts = 0;
		std::vector<Bytes> _parts;
		std::vector<Bytes> _hashmap;    // per-part map hashes (MAPHASH_LEN each)
		uint16_t _hashmap_height = 0;
		int32_t _consecutive_completed_height = -1;
		bool _waiting_for_hmu = false;
		uint8_t _window = Type::Resource::WINDOW;
		uint8_t _window_max = Type::Resource::WINDOW_MAX_SLOW;
		uint8_t _window_min = Type::Resource::WINDOW_MIN;
		double _last_activity = 0.0;
		uint8_t _retries_left = Type::Resource::MAX_RETRIES;
		uint8_t _segment_index = 1;
		uint8_t _total_segments = 1;
		uint16_t _sdu = Type::Resource::SDU;

		// Send-side state (populated by send constructor)
		std::vector<Bytes> _sent_parts;          // Pre-computed encrypted part data
		Bytes _expected_proof;                    // SHA256(original_data + hash) for validation
		uint16_t _sent_count = 0;                // Parts sent so far
		uint16_t _receiver_min_consecutive = 0;  // Receiver's reported progress

	friend class Resource;
	};

}
