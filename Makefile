NAME		=	yellow

PKG_NAME	=	yellow-1.0

RM		=	rm -f

GXX		=	g++

SRCS		=	sources/main.cpp \
			sources/LivePacketCapture.cpp \
			sources/GraphicsWindow.cpp \
			sources/GraphicsWorker.cpp

OBJS		=	$(SRCS:.cpp=.o)

CXXFLAGS	+=	-W -Iincludes `pkg-config gtkmm-3.0 --cflags`

LDFLAGS		+= `pkg-config gtkmm-3.0 --libs` -lpthread

all:		$(NAME) pkg

$(NAME):	$(OBJS)
	$(GXX) -o $(NAME) $(OBJS) $(LDFLAGS)

pkg:
	cp $(NAME) $(PKG_NAME)/usr/bin/$(NAME)
	sudo dpkg-deb --build $(PKG_NAME)

clean:
	$(RM) $(OBJS)

fclean:		clean
	$(RM) $(NAME)

pclean:
	$(RM) $(PKG_NAME)/bin/usr/$(NAME)
	$(RM) $(PKG_NAME).deb

re:		fclean pclean all

.PHONY:		all pkg clean fclean pclean re
