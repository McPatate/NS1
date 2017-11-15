#include "GraphicsWindow.hpp"

GraphicsWindow::GraphicsWindow() : m_Worker(), m_WorkerThread(nullptr)
{
  this->set_title("Yellow");
  this->set_border_width(10);

  this->_global = Gtk::Table(12, 12);
  this->GraphicInterfaces();
  this->GraphicData();
  this->GraphicCapture();
  this->GraphicFooter();

  this->_load->signal_clicked().connect(sigc::mem_fun(*this, &GraphicsWindow::OnLoadClicked));
  this->_save->signal_clicked().connect(sigc::mem_fun(*this, &GraphicsWindow::OnSaveClicked));
  this->_execute->signal_clicked().connect(sigc::mem_fun(*this, &GraphicsWindow::Execute));

  m_Dispatcher.connect(sigc::mem_fun(*this, &GraphicsWindow::OnNotificationFromWorkerThread));
  
  this->add(this->_global);
  this->show_all_children();
}

void				GraphicsWindow::Notify()
{
  m_Dispatcher.emit();
}

void				GraphicsWindow::GraphicInterfaces()
{
  std::vector<std::string>	interfaces = LivePacketCapture::Interfaces();
  Gtk::RadioButton		*radio;

  this->_interfaces_container = Gtk::VButtonBox(Gtk::BUTTONBOX_START, 10);
  for (unsigned int i = 0; i < interfaces.size(); ++i) {
    radio = Gtk::manage(new Gtk::RadioButton(this->_interfaces_group, interfaces[i]));
    this->_interfaces_container.pack_start(*radio);
    this->_interfaces.push_back(radio);    
  }
  this->_global.attach(this->_interfaces_container, 0, 2, 2, 4);
}

void				GraphicsWindow::GraphicData()
{
  this->_data_container.set_group_name("tabs");
  
  this->_ethhdr = Gtk::manage(new Gtk::Label());
  this->_iphdr = Gtk::manage(new Gtk::Label());
  this->_phdr = Gtk::manage(new Gtk::Label());
  this->_payload = Gtk::manage(new Gtk::Label());

  this->_data_container.append_page(*(this->_ethhdr), "Ethernet");
  this->_data_container.append_page(*(this->_iphdr), "IP");
  this->_data_container.append_page(*(this->_phdr), "Protocol");
  this->_data_container.append_page(*(this->_payload), "Payload");
  
  this->_global.attach(this->_data_container, 2, 8, 1, 10);
}

void				GraphicsWindow::GraphicCapture()
{
  this->_capture_container.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC);
  this->_capture_list_container = Gtk::manage(new Gtk::VBox(true, 2));
  this->_capture_container.add(*(this->_capture_list_container));
  this->_global.attach(this->_capture_container, 8, 12, 2, 10);
}

void				GraphicsWindow::GraphicFooter()
{
  this->_footer_container = Gtk::HButtonBox(Gtk::BUTTONBOX_END, 10);
  this->_path = Gtk::manage(new Gtk::Label());
  this->_load = Gtk::manage(new Gtk::Button(Gtk::Stock::FILE));
  this->_save = Gtk::manage(new Gtk::Button(Gtk::Stock::FILE));
  this->_execute = Gtk::manage(new Gtk::Button(Gtk::Stock::EXECUTE));
  this->_load->set_label("Load");
  this->_save->set_label("Save");
  this->_footer_container.pack_start(*(this->_path));
  this->_footer_container.pack_start(*(this->_load));
  this->_footer_container.pack_start(*(this->_save));
  this->_footer_container.pack_start(*(this->_execute));
  this->_global.attach(this->_footer_container, 0, 12, 10, 11);

  this->_progress_container = Gtk::Alignment(Gtk::ALIGN_CENTER, Gtk::ALIGN_END);
  this->_progress = Gtk::manage(new Gtk::ProgressBar());
  this->_progress_container.add(*(this->_progress));
  this->_global.attach(this->_progress_container, 0, 12, 11, 12);
}

void				GraphicsWindow::OnLoadClicked()
{
  Gtk::FileChooserDialog	dialog("Please choose a file", Gtk::FILE_CHOOSER_ACTION_OPEN);

  dialog.set_transient_for(*this);
  dialog.add_button("_Cancel", Gtk::RESPONSE_CANCEL);
  dialog.add_button("_Open", Gtk::RESPONSE_OK);

  int result = dialog.run();

  if(result == Gtk::RESPONSE_OK) {
    std::string filename = dialog.get_filename();
    try {
      this->_packets.clear();
      this->_packets = LivePacketCapture::Load(filename);
      this->_path->set_text(filename);
    } catch (std::string &e) {
      // Dialog alert
    }
  }
  this->Display();
}

void				GraphicsWindow::OnSaveClicked()
{
  Gtk::FileChooserDialog	dialog("Save", Gtk::FILE_CHOOSER_ACTION_SAVE);

  dialog.set_transient_for(*this);
  dialog.set_do_overwrite_confirmation(true);
  dialog.set_create_folders(true);
  dialog.add_button("_Cancel", Gtk::RESPONSE_CANCEL);
  dialog.add_button("_Save", Gtk::RESPONSE_OK);

  int result = dialog.run();

  if(result == Gtk::RESPONSE_OK) {
    std::string filename = dialog.get_filename();

    if (this->_path->get_text().size() > 0) {
      
      std::ifstream		src(this->_path->get_text().c_str(), std::ios::binary);
      std::ofstream		dest(filename.c_str(), std::ios::binary | std::ios::trunc);
      
      dest << src.rdbuf();
      src.close();
      dest.close();
      this->_path->set_text(filename);
    } else {
      try {
	for (unsigned int i = 0; i < this->_packets.size(); ++i) {
	  LivePacketCapture::Write(filename, this->_packets[i]);
	}
	this->_path->set_text(filename);
      } catch (std::string &e) {
	// Dialog alert
      }
    }
  }
  this->Display();
}

void				GraphicsWindow::OnCaptureClicked(unsigned int i)
{
  this->_ethhdr->set_text(LivePacketCapture::ReadEthernet(this->_packets[i]));
  this->_iphdr->set_text(LivePacketCapture::ReadIP(this->_packets[i]));
  switch (this->_packets[i].iph.protocol) {
  case ICMP:
    this->_phdr->set_text(LivePacketCapture::ReadICMP(this->_packets[i]));
    break;
  case TCP:
    this->_phdr->set_text(LivePacketCapture::ReadTCP(this->_packets[i]));
    break;
  case UDP:
    this->_phdr->set_text(LivePacketCapture::ReadUDP(this->_packets[i]));
    break;
  }  
  this->_payload->set_text(LivePacketCapture::ReadPayload(this->_packets[i]));
}

void				GraphicsWindow::OnNotificationFromWorkerThread()
{
  if (m_WorkerThread && m_Worker.has_stopped())
    {
      // Work is done.
      if (m_WorkerThread->joinable())
	m_WorkerThread->join();
      delete m_WorkerThread;
      m_WorkerThread = nullptr;
      
      this->_execute->set_label("Execute");
    }

  double			fraction;
  packet_t			packet;

  m_Worker.get_data(&fraction, &packet);  
  this->_progress->set_fraction(fraction);
  this->_packets.push_back(packet);
  this->Display();
}

void				GraphicsWindow::Execute()
{
  this->_path->set_text("");
  if (m_WorkerThread)
    {
      m_Worker.stop_work();
      this->_execute->set_label("Execute");
    }
  else
    {
      this->_packets.clear();
      this->_execute->set_label("Stop");
      m_WorkerThread = new std::thread([this] { m_Worker.do_work(this); });
    }
  this->Display();
}

void				GraphicsWindow::Display()
{
  Gtk::Button			*button;
  struct sockaddr_in		source;

  for (unsigned int i = 0; i < this->_capture_list.size(); ++i) {
    delete this->_capture_list[i];
  }
  this->_capture_list.clear();
  for (unsigned int i = 0; i < this->_packets.size(); ++i) {
    std::stringstream		ss;
    
    memset(&source, 0, sizeof(struct sockaddr_in));
    source.sin_addr.s_addr = this->_packets[i].iph.saddr;
    ss << i << ": " << inet_ntoa(source.sin_addr);
    button = Gtk::manage(new Gtk::Button(ss.str()));
    button->signal_clicked().connect(sigc::bind<unsigned int>(sigc::mem_fun(*this, &GraphicsWindow::OnCaptureClicked), i));
    this->_capture_list_container->pack_start(*button);
    this->_capture_list.push_back(button);
  }
  this->show_all_children();
}
