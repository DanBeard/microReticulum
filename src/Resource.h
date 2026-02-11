#pragma once

#include "Destination.h"
#include "Type.h"

#include <memory>
#include <cassert>

namespace RNS {

	class ResourceData;
	class Packet;
	class Destination;
	class Link;
	class Resource;

	class Resource {

	public:
		class Callbacks {
		public:
			// CBA std::function apparently not implemented in NRF52 framework
			//typedef std::function<void(const Resource& resource)> concluded;
			using concluded = void(*)(const Resource& resource);
			using progress = void(*)(const Resource& resource);
		public:
			concluded _concluded = nullptr;
			progress _progress = nullptr;
		friend class Resource;
		};

	public:
		Resource(Type::NoneConstructor none) {
			MEM("Resource NONE object created");
		}
		Resource(const Resource& resource) : _object(resource._object) {
			MEM("Resource object copy created");
		}
		//Resource(const Link& link = {Type::NONE});
		Resource(const Bytes& data, const Link& link, const Bytes& request_id, bool is_response, double timeout);
		Resource(const Bytes& data, const Link& link, bool advertise = true, bool auto_compress = true, Callbacks::concluded callback = nullptr, Callbacks::progress progress_callback = nullptr, double timeout = 0.0, int segment_index = 1, const Bytes& original_hash = {Type::NONE}, const Bytes& request_id = {Type::NONE}, bool is_response = false);
		virtual ~Resource(){
			MEM("Resource object destroyed");
		}

		Resource& operator = (const Resource& resource) {
			_object = resource._object;
			return *this;
		}
		operator bool() const {
			return _object.get() != nullptr;
		}
		bool operator < (const Resource& resource) const {
			return _object.get() < resource._object.get();
			//return _object->_hash < resource._object->_hash;
		}

	public:
		static Resource accept(const Packet& advertisement_packet, Callbacks::concluded callback = nullptr, Callbacks::progress progress_callback = nullptr, const Bytes& request_id = {Type::NONE});

	public:
		Bytes get_map_hash(const Bytes& data) const;
		void hashmap_update(uint16_t segment, const Bytes& hashmap_data);
		void hashmap_update_packet(const Bytes& plaintext);
		void receive_part(const Packet& packet);
		void request_next();
		void assemble();
		void prove();
		void validate_proof(const Bytes& proof_data);
		// Send-side methods
		void advertise();
		void request(const Bytes& request_data);
		void send_hashmap_update(uint16_t segment);
		void cancel();
		float get_progress() const;
		void set_concluded_callback(Callbacks::concluded callback);
		void set_progress_callback(Callbacks::progress callback);

		std::string toString() const;

		// getters
		const Bytes& hash() const;
		const Bytes& request_id() const;
		const Bytes& data() const;
		const Type::Resource::status status() const;
		const size_t size() const;
		const size_t total_size() const;
		const Link& link() const;
		bool initiator() const;

		// setters

	protected:
		std::shared_ptr<ResourceData> _object;

	};


	class ResourceAdvertisement {
	public:
		static ResourceAdvertisement unpack(const Bytes& data);
		static Bytes pack(const ResourceAdvertisement& adv);
		static bool is_request(const Packet& advertisement_packet);
		static bool is_response(const Packet& advertisement_packet);
		static Bytes read_request_id(const Packet& advertisement_packet);
		static size_t read_transfer_size(const Packet& advertisement_packet);
		static size_t read_size(const Packet& advertisement_packet);

	public:
		size_t t = 0;          // transfer size (encrypted)
		size_t d = 0;          // data size (uncompressed)
		uint16_t n = 0;        // number of parts
		Bytes h;               // resource hash
		Bytes r;               // random hash
		Bytes o;               // original hash
		Bytes m;               // hashmap (raw bytes)
		uint8_t f = 0;         // flags
		uint8_t i = 1;         // segment index
		uint8_t l = 1;         // total segments
		Bytes q;               // request id

		// Decoded flags
		bool e = false;        // encrypted
		bool c = false;        // compressed
		bool s = false;        // split
		bool u = false;        // is_request
		bool p = false;        // is_response
		bool x = false;        // has_metadata
	};

}
