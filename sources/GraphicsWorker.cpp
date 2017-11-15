#include "GraphicsWorker.hpp"
#include "GraphicsWindow.hpp"
#include <sstream>
#include <chrono>

GraphicsWorker::GraphicsWorker() :
  m_Mutex(),
  m_shall_stop(false),
  m_has_stopped(false),
  m_fraction(0.0)
{
}

void GraphicsWorker::GetData(double* fraction, packet_t* packet) const
{
  std::lock_guard<std::mutex> lock(m_Mutex);

  if (fraction)
    *fraction = m_fraction;

  if (packet)
    *packet = m_packet;
}

void GraphicsWorker::StopWork()
{
  std::lock_guard<std::mutex> lock(m_Mutex);
  m_shall_stop = true;
}

bool GraphicsWorker::HasStopped() const
{
  std::lock_guard<std::mutex> lock(m_Mutex);
  return m_has_stopped;
}

void GraphicsWorker::DoWork(GraphicsWindow* caller)
{
  {
    std::lock_guard<std::mutex> lock(m_Mutex);
    m_has_stopped = false;
    m_fraction = 0.0;
    memset(&m_packet, 0, sizeof(packet_t));
  }
  
  std::string			interface;
  
  for (unsigned int i = 0; i < caller->_interfaces.size(); ++i) {
    if (caller->_interfaces[i]->get_active())
      interface = caller->_interfaces[i]->get_label();
  }
  
  LivePacketCapture		lpc(interface);
  
  for (int i = 0; ; ++i)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(250));
      
      {
	std::lock_guard<std::mutex> lock(m_Mutex);


	if (m_shall_stop)
	  {
	    memset(&m_packet, 0, sizeof(packet_t));
	    break;
	  }
	
	m_packet = lpc.Capture();
      }
      
      caller->Notify();
    }
  
  {
    std::lock_guard<std::mutex> lock(m_Mutex);
    m_shall_stop = false;
    m_has_stopped = true;
  }
  
  caller->Notify();
}
