/***************************************************************************
 *            fwClient.h
 *
 *  Copyright  2016  mc
 *  <mcarmen@<host>>
 ****************************************************************************/
#include "fwClient.h"

/**
 * Function that sets the field addr->sin_addr.s_addr from a host name
 * address.
 * @param addr struct where to set the address.
 * @param host the host name to be converted
 * @return -1 if there has been a problem during the conversion process.
 */
int setaddrbyname(struct sockaddr_in *addr, char *host)
{
  struct addrinfo hints, *res;
	int status;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  if ((status = getaddrinfo(host, NULL, &hints, &res)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
    return -1;
  }

  addr->sin_addr.s_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;

  freeaddrinfo(res);

  return 0;
}


/**
 * Returns the port specified as an application parameter or the default port
 * if no port has been specified.
 * @param argc the number of the application arguments.
 * @param an array with all the application arguments.
 * @return  the port number from the command line or the default port if
 * no port has been specified in the command line. Returns -1 if the application
 * has been called with the wrong parameters.
 */
int getPort(int argc, char* argv[])
{
  int param;
  int port = DEFAULT_PORT;

  optind=1;
  // We process the application execution parameters.
	while((param = getopt(argc, argv, "h:p:")) != -1){
		switch((char) param){
		  case 'h': break;
			case 'p':
			  // We modify the port variable just in case a port is passed as a
			  // parameter
				port = atoi(optarg);
				break;
			default:
				printf("Parametre %c desconegut\n\n", (char) param);
				port = -1;
		}
	}

	return port;
}

/**
 * Returns the host name where the server is running.
 * @param argc the number of the application arguments.
 * @param an array with all the application arguments.
 * @Return Returns the host name where the server is running.<br />
 * Returns null if the application has been called with the wrong parameters.
 */
 char * getHost(int argc, char* argv[]){
  char * hostName = NULL;
  int param;

  optind=1;
    // We process the application execution parameters.
	while((param = getopt(argc, argv, "h:p:")) != -1){
		switch((char) param){
			case 'p': break;
			case 'h':
        hostName = (char*) malloc(sizeof(char)*strlen(optarg)+1);
				// Un cop creat l'espai, podem copiar la cadena
				strcpy(hostName, optarg);
				break;
			default:
				printf("Parametre %c desconegut\n\n", (char) param);
				hostName = NULL;
		}
	}

	printf("in getHost host: %s\n", hostName); //!!!!!!!!!!!!!!
	return hostName;
 }



/**
 * Shows the menu options.
 */
void print_menu()
{
		// Mostrem un menu perque l'usuari pugui triar quina opcio fer

		printf("\nAplicació de gestió del firewall\n");
		printf("  0. Hello\n");
		printf("  1. Llistar les regles filtrat\n");
		printf("  2. Afegir una regla de filtrat\n");
		printf("  3. Modificar una regla de filtrat\n");
		printf("  4. Eliminar una regla de filtrat\n");
		printf("  5. Eliminar totes les regles de filtrat.\n");
		printf("  6. Sortir\n\n");
		printf("Escull una opcio: ");
}


/**
 * Sends a HELLO message and prints the server response.
 * @param sock socket used for the communication.
 */
void process_hello_operation(int sock)
{
  /*---- enviem el codi de peticio de Hello ----*/
  struct hello_rp hello_rp;
  hello_rp.opcode = MSG_HELLO;
  char buffer[MAX_BUFF_SIZE];
  memset(buffer, '\0', sizeof(buffer)); //inicialitzar a 0
  stshort(hello_rp.opcode, &buffer);

  send(sock, buffer, sizeof(hello_rp.opcode), 0);
  int offset = 0;
  /*---- tractem la resposta del servidor ----*/
  recv(sock, buffer, sizeof(buffer), 0);
  hello_rp.opcode = ldshort(buffer);
  printf("Opcode rebut server: %hu\n", hello_rp.opcode);
  offset += sizeof(hello_rp.opcode);
  memcpy(hello_rp.msg, &buffer[offset], sizeof(hello_rp.msg));
  printf("Msg rebut server: %s\n", hello_rp.msg);

}

void mostra_rules(char buffer[MAX_BUFF_SIZE]){
  unsigned short code;
  int offset = 0;
  code = ldshort(buffer);
  printf("Opcode rebut del server %hu\n", code);
  offset += sizeof(code);
  /*---- llegim el codi del server ----*/
  /*---- llegim el # de regles ----*/
  unsigned short num_rules;
  num_rules = ldshort(&buffer[offset]);
  offset += sizeof(num_rules);
  if (num_rules == 0){
    printf("\nEncara no s'ha afegit cap regla\n\n");
  }
  else{
    printf("\nRegles de FORWARD:\n");
    int i;
    /*---- llegim cada regla ----*/
    for (i = 1; i <= num_rules; i++){
      /*---- llegim la addr del buffer ----*/
      struct in_addr ip_addr;
      memcpy(&ip_addr.s_addr, &buffer[offset], sizeof(ip_addr.s_addr));
      offset += sizeof(ip_addr.s_addr);
      char flag[MAX_SRC_DST_STR_SIZE], flag_port[MAX_SRC_DST_STR_SIZE];
      unsigned short netmask,port, f_addr, f_port;
      /*---- llegim el flag del addr del buffer ----*/
      f_addr = ldshort(&buffer[offset]);
      if (f_addr == SRC){
        strcpy(flag, SRC_STR);
      }
      else if (f_addr == DST){
        strcpy(flag, DST_STR);
      }
      offset += sizeof(f_addr);
      /*---- llegim la netmask del buffer ----*/
      netmask = ldshort(&buffer[offset]);
      offset += sizeof(netmask);
      /*---- llegim el flag del port del buffer ----*/
      f_port = ldshort(&buffer[offset]);
      offset += sizeof(f_port);
      /*---- llegim el numero del port del buffer ----*/
      port = ldshort(&buffer[offset]);
      offset += sizeof(port);
      if (port == 0){ //no ha especificat port
        printf("%d: %s/%hu %s\n", i, inet_ntoa(ip_addr), netmask, flag);
      }
      else if (port != 0){
        if (f_port == SRC){
          strcpy(flag_port, SRC_PORT_STR);
        }
        else if (f_port == DST){
          strcpy(flag_port, DST_PORT_STR);
        }
        printf("%d: %s/%hu %s %s %hu\n", i, inet_ntoa(ip_addr), netmask, flag, flag_port, port);
      }
    }
  }
}

/**
* Function that recieves a buffer from the server containing
* the set of rules stored in the server
* @param sock the communications socket
*/
void process_list_rules(int sock){
  /*---- enviem la peticio ----*/
  unsigned short code = MSG_LIST;
  char buffer[MAX_BUFF_SIZE];
  memset(buffer, '\0', sizeof(buffer)); //inicialitzar a 0
  stshort(code, &buffer);
  send(sock, buffer, sizeof(code), 0);
  /*---- llegim les regles rebudes ----*/
  recv(sock, buffer, sizeof(buffer), 0); //buffer amb la llista
  mostra_rules(buffer);
  

}
/**
* Function that recieves the client's inputs, specifying the parameters
* of the new rule to be added and sends it to the server
* @param sock the communications socket
*/
void add_rule(int sock){
  unsigned short code = MSG_ADD;
  char buffer[MAX_BUFF_SIZE];
  memset(buffer, '\0', sizeof(buffer)); //inicialitzar a 0
  /*---- afegim el codi ----*/
  stshort(code, &buffer);
  int offset = 0;
  offset += sizeof(code);
  printf("Afegir nova regla\nIntrodueix la regla seguint el format:\n"
  "address src|dst Netmask [sport|dport] [port]\n");
  char ip[MAX_ADDR_SIZE],flag[MAX_SRC_DST_STR_SIZE], flag_port[MAX_SRC_DST_STR_SIZE];
  unsigned short netmask,port, f_addr, f_port;
  scanf("%s %s %hu %s %hu", ip, flag, &netmask, flag_port, &port);
  struct in_addr ip_addr;
  inet_aton(ip, &ip_addr);
  memcpy(&buffer[offset], &ip_addr.s_addr, sizeof(ip_addr.s_addr));
  offset += sizeof(ip_addr);
  if (strcmp(flag, SRC_STR) == 0){
    f_addr= SRC;
  }
  else if (strcmp(flag, DST_STR) == 0){
    f_addr = DST;
  }
  stshort(f_addr, &buffer[offset]);
  offset += sizeof(f_addr);
  stshort(netmask, &buffer[offset]);
  offset += sizeof(netmask);
  if (strcmp(flag_port, SRC_PORT_STR) == 0){
    f_port = SRC;
  }
  else if (strcmp(flag_port, DST_PORT_STR) == 0){
    f_port = DST;
  }
  stshort(f_port, &buffer[offset]);
  offset += sizeof(f_port);
  stshort(port, &buffer[offset]);
  offset += sizeof(port);
  send(sock, buffer, offset,0);
  /*---- llegim les regles rebudes ----*/
  recv(sock, buffer, sizeof(buffer), 0); //buffer amb la llista
  code = ldshort(buffer);
  if (code == MSG_OK){
    printf(OK_MSG);
    printf("\n");
  }

}

/**
 * Closes the socket connected to the server and finishes the program.
 * @param sock socket used for the communication.
 */
void process_exit_operation(int sock)
{
  unsigned short code = MSG_FINISH;
  char buffer[MAX_BUFF_SIZE];
  memset(buffer, '\0', sizeof(buffer)); //inicialitzar a 0
  stshort(code, &buffer);
  send(sock, buffer, sizeof(code), 0);
  close(sock);
  exit(0);
}

void process_change_rule(int sock){
  unsigned short code = MSG_CHANGE;
  char buffer[MAX_BUFF_SIZE];
  memset(buffer, '\0', sizeof(buffer)); //inicialitzar a 0
  stshort(code, &buffer);
  int offset = 0;
  offset += sizeof(code);
  printf("Modificar una regla\nIntrodueix la regla seguint el format:\n"
  "id address src|dst Netmask [sport|dport] [port]\n");
  char ip[MAX_ADDR_SIZE];
  char flag[MAX_SRC_DST_STR_SIZE], flag_port[MAX_SRC_DST_STR_SIZE];
  unsigned short id,netmask,port, f_addr, f_port;
  scanf("%hu %s %s %hu %s %hu", &id, ip, flag, &netmask, flag_port, &port);
  stshort(id, &buffer[offset]);
  offset += sizeof(id);
  struct in_addr ip_addr;
  inet_aton(ip, &ip_addr);
  memcpy(&buffer[offset], &ip_addr.s_addr, sizeof(ip_addr.s_addr));
  offset += sizeof(ip_addr);
  if (strcmp(flag, SRC_STR) == 0){
    f_addr= SRC;
  }
  else if (strcmp(flag, DST_STR) == 0){
    f_addr = DST;
  }
  stshort(f_addr, &buffer[offset]);
  offset += sizeof(f_addr);
  stshort(netmask, &buffer[offset]);
  offset += sizeof(netmask);
  if (strcmp(flag_port, SRC_PORT_STR) == 0){
    f_port = SRC;
  }
  else if (strcmp(flag_port, DST_PORT_STR) == 0){
    f_port = DST;
  }
  stshort(f_port, &buffer[offset]);
  offset += sizeof(f_port);
  stshort(port, &buffer[offset]);
  offset += sizeof(port);
  send(sock, buffer, offset,0);

/*---- esperem la resposta ----*/
  recv(sock, buffer, sizeof(buffer), 0); //buffer amb la llista
  code = ldshort(&buffer);
  offset = 0;
  offset += sizeof(code);
  if (code == MSG_ERR){ 
    printf(NOK_MSG);
    printf("\n");
    code = ldshort(&buffer[offset]);
    if (code == ERR_RULE){
      printf(ERR_MSG_RULE);
      printf("\n");
    }
  }
  else if (code == MSG_OK){
    printf(OK_MSG);
    printf("\n");
  }
}

void process_delete_rule(int sock){
  unsigned short code = MSG_DELETE;
  char buffer[MAX_BUFF_SIZE];
  memset(buffer, '\0', sizeof(buffer)); //inicialitzar a 0
  stshort(code, &buffer);
  int offset = 0;
  offset += sizeof(code);
  printf("Introdueix la id de la regla a eliminar\n");
  unsigned short id;
  scanf("%hu", &id);
  stshort(id, &buffer[offset]);
  offset += sizeof(id);
  send(sock, buffer, offset, 0);
  /*---- esperem la resposta ----*/
  recv(sock, buffer, sizeof(buffer), 0); //buffer amb la llista
  code = ldshort(buffer);
  offset = 0;
  offset += sizeof(code);
  if (code == MSG_ERR){
    printf(NOK_MSG);
    printf("\n");
    code = ldshort(&buffer[offset]);
    if (code == ERR_RULE){
      printf(ERR_MSG_RULE);
      printf("\n");
    }
  }
  else if (code == MSG_OK){
    printf(OK_MSG);
    printf("\n");
  }

}

/**
 * Function that deletes ALL the rules
 * stored in the server
 * @param sock The communications socket
 */

void process_flush(int sock){
  unsigned short code = MSG_FLUSH;
  char buffer[MAX_BUFF_SIZE];
  memset(buffer, '\0', sizeof(buffer)); //inicialitzar a 0
  stshort(code, &buffer);
  send(sock, buffer, sizeof(code), 0);
  /*---- esperem la resposta ----*/
  recv(sock, buffer, sizeof(buffer), 0); //buffer amb la llista
  code = ldshort(&buffer);
  int offset = 0;
  offset += sizeof(code);
  if (code == MSG_ERR){
    printf(NOK_MSG);
    printf("\n");
    code = ldshort(&buffer[offset]);
    if (code == ERR_RULE){
      printf(ERR_MSG_RULE);
      printf("\n");
    }
  }
  else if (code == MSG_OK){
    printf(OK_MSG);
    printf("\n");
  }
}


/**
 * Function that process the menu option set by the user by calling
 * the function related to the menu option.
 * @param s The communications socket
 * @param option the menu option specified by the user.
 */
void process_menu_option(int s, int option)
{
  switch(option){
    // Opció HELLO
    case MENU_OP_HELLO:
      process_hello_operation(s);
      break;
    case MENU_OP_LIST_RULES:
      process_list_rules(s);
      break;
    case MENU_OP_ADD_RULE:
      add_rule(s);
      break;
    case MENU_OP_CHANGE_RULE:
      process_change_rule(s);
      break;
    case MENU_OP_DEL_RULE:
      process_delete_rule(s);
      break;
    case MENU_OP_FLUSH:
      process_flush(s);
      break;
    case MENU_OP_EXIT:
      process_exit_operation(s);
      break;
    default:
      printf("Invalid menu option\n");
  }
}


int main(int argc, char *argv[]){
  int s = 0;
  unsigned short port;
  char *hostName;
  int menu_option = 0;
  port = getPort(argc, argv);
  hostName = getHost(argc, argv);

  //Checking that the host name has been set.Otherwise the application is stopped.
	if(hostName == NULL){
		perror("No s'ha especificat el nom del servidor\n\n");
		return -1;
	}

  //creem el socket client
  s = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
  if (s < 0){
    printf("\nError : Could not create socket \n");
    return 1;
  }
  struct sockaddr_in client_addr;
  socklen_t client_addrlen = sizeof(client_addr);
  client_addr.sin_family = AF_INET;
  client_addr.sin_port = htons(port);
  setaddrbyname(&client_addr,hostName);
  if (connect(s, (struct sockaddr *) &client_addr, client_addrlen) < 0){
      printf("\nError : Connect Failed \n");
      return 1;
  }
  do{
      print_menu();
		  // getting the user input.
		  scanf("%d",&menu_option);
		  printf("\n\n");
		  process_menu_option(s, menu_option);

	  }while(menu_option != MENU_OP_EXIT); //end while(opcio)

  return 0;
}
