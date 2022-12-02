# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: lumenthi <lumenthi@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2017/12/22 14:06:43 by lumenthi          #+#    #+#              #
#    Updated: 2022/12/02 07:49:37 by lumenthi         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = ft_malcolm

CC = gcc
FLAGS = -Wall -Werror -Wextra -g
LDFLAGS =

GREEN = '\033[4;32m'
RED = '\033[4;31m'
BLANK = '\033[0m'
YELLOW = '\033[4;33m'
CYAN = '\033[4;38;5;51m'
WARNING = '\033[1;33m'
RESET = '\033[0m'
COMPILE_COLOR = '\033[0;33m'

TICK = '\033[1;32m~\033[0m'
CROSS = '\033[1;31mx\033[0m'

###### FOLDERS ######

LIBDIR = libft
SRCDIR = sources
HEADDIR = headers
OBJDIR = objs

#####################

#####################

###### LIBRARY ######

LIBFT = $(LIBDIR)/libft.a

#####################

###### HEADERS ######

HEADS = malcolm.h \
		options.h
HEADERS = $(addprefix $(HEADDIR)/, $(HEADS))

#####################

###### SOURCES ######

SRCS =	main.c \
		parse_option_line.c \
		print.c \
		signal.c \
		help.c

SOURCES = $(addprefix $(SRCDIR)/, $(SRCS))

#####################

###### OBJECTS ######

OBJS = $(addprefix $(OBJDIR)/, $(SRCS:.c=.o))

#####################

###### DEPENDENCIES ######

DEP = $(OBJS:.o=.d)

#####################

TODOS=$(shell grep -nr "TODO" $(SRCDIR) $(HEADDIR) | wc -l)

SHOULD_COUNT=1
FILES_TO_COMPILE = 0
ifeq ($(SHOULD_COUNT), 1)
	FILES_TO_COMPILE:=$(shell make -n SHOULD_COUNT=0 | grep "gcc -c" | wc -l)
endif

all:
	@ $(MAKE) -s -C $(LIBDIR)
	@ $(MAKE) --no-print-directory $(NAME)

###### BINARY COMPILATION ######

$(NAME): $(LIBFT) $(OBJS) ${HEADERS}
	@ printf "[Linking] "
	$(CC) $(OBJS) -o $(NAME) $(LIBFT) $(LDFLAGS)
	@ printf " %b | Compiled %b%b%b\n" $(TICK) $(GREEN) $(NAME) $(BLANK)
	@ if [ $(TODOS) -gt 0 ]; then\
		printf "%b[WARNING]%b You have %d TODOs pending, run make todo to check them.\n"\
			$(WARNING) $(BLANK) $(TODOS);\
	fi

###############################

$(LIBFT):
	 @ $(MAKE) -s -C $(LIBDIR)

-include $(DEP)

I = 1
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@ mkdir -p $(OBJDIR)
	@ printf "[$(I)/$(FILES_TO_COMPILE)] "
	$(CC) -c -MMD -MF $(patsubst %.o,%.d,$@) $(FLAGS) -I$(HEADDIR) -I$(LIBDIR) -o $@ $<
	$(eval I=$(shell echo $$(($(I) + 1))))

$(DEPDIR)/%.d: $(SRCDIR)/%.c
	@ mkdir -p $(DEPDIR)
	$(CC) -c -MMD $(FLAGS) -I$(HEADDIR) -I$(LIBDIR) -o $@ $<

clean:
	@ $(MAKE) -s -C $(LIBDIR) clean
	@ test -d $(OBJDIR) && \
	rm -rf $(OBJDIR) && \
	printf " %b | " $(TICK) && \
	printf "Removed %bobjects%b folders\n" $(YELLOW) $(BLANK) \
	|| (printf " %b | " $(CROSS) && \
	printf "No %bobjects%b folders\n" $(YELLOW) $(BLANK))

fclean: clean
	@ test -f $(LIBFT) && \
	rm -rf $(LIBFT) && \
	printf " %b | " $(TICK) && \
	printf "Removed %blibft%b library\n" $(RED) $(BLANK) \
	|| (printf " %b | " $(CROSS) && \
	printf "No %blibft%b library\n" $(RED) $(BLANK))
	@ test -f $(NAME) && \
	rm -rf $(NAME) && \
	printf " %b | " $(TICK) && \
	printf "Removed %b%b%b binary\n" $(RED) $(NAME) $(BLANK) \
	|| (printf " %b | " $(CROSS) && \
	printf "No %b%b%b binary\n" $(RED) $(NAME) $(BLANK))

re: fclean # Make -j support
	@ $(MAKE) all

todo:
	@ printf "%b" $(WARNING)
	@ grep -nr "TODO" $(SRCDIR) $(HEADDIR) || true
	@ printf "%b" $(BLANK)

run:
	@ $(MAKE) all
	@ sudo ./$(NAME) 172.17.0.1 66:66:66:66:66:66 172.17.0.2 02:42:ac:11:00:02

.PHONY: all clean fclean re todo run
