#ifndef __CAP_DEVICE__
#define __CAP_DEVICE__

#include <string>

namespace cap
{
	typedef struct
	{
		unsigned int recv;		// number of packets received
		unsigned int drop;		// number of packets dropped
		unsigned int ifdrop;	// drops by interface
	} stats;

	struct filter;
	class device
	{
	protected:
		volatile bool is_closed_;
	protected:
		device();
	public:
		virtual ~device();
	public:
		virtual bool open(int mode = 0) = 0;
		virtual void close(void) = 0;
	public:
		virtual bool get_statistics(stats& st) const = 0;
	public:
		bool is_open(void) const;
	};
}

#endif
