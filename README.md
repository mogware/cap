# wrapper for pcap/winpcap

## Usage

Example of simple capture class

```c++
class capture
{
	int count_;
public:
	capture(void) : count_(0) {}
public:
	void run(void)
	{
		using namespace std::placeholders;

		std::shared_ptr<cap::live_device> dev =
			cap::live_device_list::default_device();
		dev->open(cap::promisc);
		dev->add_callback(std::bind(&capture::on_packet, this, _1));
		dev->start();
		dev->wait();
		dev->close();
	}
public:
	bool on_packet(const std::shared_ptr<cap::packet>& pkt)
	{
		return ++count_ < 100 ? false : true;
	}
};
```