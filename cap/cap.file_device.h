#ifndef __CAP_FILE_DEVICE__
#define __CAP_FILE_DEVICE__

#include <memory>
#include <vector>

#include "cap.device.h"
#include "cap.filter.h"
#include "cap.packet.h"

namespace cap
{
	class file_device : public device
	{
	protected:
		std::string file_name_;
	protected:
		file_device(const char* name);
		virtual ~file_device(void);
	public:
		std::string get_file_name(void);
	};

	class file_reader_device : public file_device
	{
	protected:
		std::uint32_t packets_read_;
	protected:
		file_reader_device(const char* name);
	public:
		virtual ~file_reader_device(void);
	public:
		static std::shared_ptr<file_reader_device> of(const char* name);
	public:
		std::uint64_t get_size(void) const;
		bool get_statistics(stats& st) const;
	public:
		virtual bool set_filter(const std::string& filt) = 0;
	public:
		bool set_filter(const std::shared_ptr<filter>& filt);
		void clear_filter(void);
	public:
		virtual std::shared_ptr<packet> get_next_packet(void) const = 0;
	public:
		int get_next_packets(std::vector<std::shared_ptr<packet>>& pkts, int count = 0) const;
	};

	class file_writer_device : public file_device
	{
	protected:
		std::uint32_t packets_written_;
		std::uint32_t packets_not_written_;
	protected:
		file_writer_device(const char* name);
	public:
		virtual ~file_writer_device(void);
	public:
		static std::shared_ptr<file_writer_device> of(const char* name);
	public:
		bool get_statistics(stats& st) const;
	public:
		virtual bool write_packet(const std::shared_ptr<packet>& pkt) = 0;
		virtual bool write_packets(const std::vector<std::shared_ptr<packet>>& pkts) = 0;
	};
}

#endif
