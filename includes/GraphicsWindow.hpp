#ifndef _GRAPHICSWINDOW_HPP_
# define _GRAPHICSWINDOW_HPP_

# include <gtkmm.h>

# include <vector>
# include <fstream>
# include <sstream>

# include "GraphicsWorker.hpp"

class					GraphicsWindow : public Gtk::Window
{
public:
  GraphicsWindow();
  virtual ~GraphicsWindow() {}

  void					Notify();
  
  std::vector<Gtk::RadioButton *>	_interfaces;
private:
  void					GraphicInterfaces();
  void					GraphicData();
  void					GraphicCapture();
  void					GraphicFooter();

  void					OnLoadClicked();
  void					OnSaveClicked();
  void					OnCaptureClicked(unsigned int i);
  void					OnNotificationFromWorkerThread();
  
  void					Execute();
  void					Display();
  
  std::vector<packet_t>			_packets;

  Gtk::Table				_global;
  
  Gtk::Notebook				_data_container;
  Gtk::Label				*_ethhdr;
  Gtk::Label				*_iphdr;
  Gtk::Label				*_phdr;
  Gtk::Label				*_payload;
  
  Gtk::ScrolledWindow			_capture_container;
  Gtk::VBox				*_capture_list_container;
  std::vector<Gtk::Button *>		_capture_list;

  // INTERFACES
  Gtk::VButtonBox			_interfaces_container;
  Gtk::RadioButtonGroup			_interfaces_group;
  // !INTERFACES

  // FOOTER
  Gtk::HButtonBox			_footer_container;
  Gtk::Label				*_path;
  Gtk::Button				*_load;
  Gtk::Button				*_save;
  Gtk::Button				*_execute;

  Gtk::Alignment			_progress_container;
  Gtk::ProgressBar			*_progress;
  // !FOOTER

  Glib::Dispatcher m_Dispatcher;
  GraphicsWorker m_Worker;
  std::thread* m_WorkerThread;
};

#endif // !_GRAPHICSWINDOW_HPP_
