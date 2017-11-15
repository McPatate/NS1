#include <gtkmm/main.h>
#include "GraphicsWindow.hpp"

int				main(int argc, char *argv[])
{
  Gtk::Main			app(argc, argv);
  GraphicsWindow		window;

  Gtk::Main::run(window);
  return 0;
}
