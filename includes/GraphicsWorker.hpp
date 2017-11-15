#ifndef _GRAPHICSWORKER_HPP_
# define _GRAPHICSWORKER_HPP_

# include <gtkmm.h>
# include <thread>
# include <mutex>
# include "LivePacketCapture.hpp"

class					GraphicsWindow;

class					GraphicsWorker
{
public:
  GraphicsWorker();
  virtual ~GraphicsWorker() {}
  
public:
  void DoWork(GraphicsWindow* caller);

  void GetData(double* fraction, packet_t *packet) const;
  void StopWork();
  bool HasStopped() const;

private:
  mutable std::mutex m_Mutex;

  bool m_shall_stop;
  bool m_has_stopped;
  double m_fraction;
  packet_t m_packet;
};

#endif // !_GRAPHICSWORKER_HPP_
