#include "cap.device.h"

cap::device::device()
	: is_closed_(true)
{
}

cap::device::~device()
{
}

bool cap::device::is_open(void) const
{
	return !is_closed_;
}
