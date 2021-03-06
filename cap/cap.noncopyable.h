#ifndef __CAP_NONCOPYABLE__
#define __CAP_NONCOPYABLE__

namespace cap
{
	class noncopyable
	{
	protected:
		constexpr noncopyable() = default;
		~noncopyable() = default;
	protected:
		noncopyable(const noncopyable&) = delete;
		noncopyable(noncopyable&&) = delete;
	protected:
		noncopyable& operator=(const noncopyable&) = delete;
		noncopyable& operator=(noncopyable&&) = delete;
	};
}

#endif

