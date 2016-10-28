/***************************************************************************
 *            fwServer.c
 *
 *  Copyright  2016  mc
 *  <mc@<host>>
 ****************************************************************************/

#include "fwServer.h"

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
	while((param = getopt(argc, argv, "p:")) != -1){
		switch((char) param){
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
 * Function that sends a HELLO_RP to the  client
 * @param sock the communications socket
 */
void process_HELLO_msg(int sock)
{
  /*---- creem la estructura Hello per enviar al client ----*/
  struct hello_rp hello_rp;
  hello_rp.opcode = MSG_HELLO_RP;
  strcpy(hello_rp.msg, "Hello World");
  char buffer[MAX_BUFF_SIZE];
  memset(buffer, '\0', sizeof(buffer)); //inicialitzar a 0
  int offset = 0;
  stshort(hello_rp.opcode, buffer);
  offset += sizeof(hello_rp.opcode);
  memcpy(&buffer[offset], &hello_rp.msg, sizeof(hello_rp.msg));
  offset += sizeof(hello_rp.msg);
  send(sock, buffer, offset, 0);
  //TODO
}


/**
* Function that returns to the client a list of the rules
* @param sock the communications socket
* @param chain the chain of rules
*/
void process_list_rules(int sock, struct FORWARD_chain *chain){
  unsigned short code = MSG_RULES;
  char buffer[MAX_BUFF_SIZE];
  memset(buffer, '\0', sizeof(buffer)); //inicialitzar a 0
  int offset = 0;
  unsigned short num_rules = chain->num_rules;
  
  /*---- posem el codi al buffer ----*/
  stshort(code, buffer); //opcode
  offset += sizeof(code);
  /*---- posem el # de regles al buffer ----*/
  stshort(num_rules, &buffer[offset]); //#rules
  offset += sizeof(num_rules);
  if (chain->num_rules == 0){
    printf("%hu\n", code);
    send(sock, buffer, offset, 0);
  }
  else {
    /*---- creem un apuntador per recorrer la cadena de regles ----*/
    struct fw_rule *aux_rule; // conte rule i apuntadr a next_rule
    aux_rule = chain->first_rule; //es un apuntador
    int i;
    for (i = 0; i < num_rules; i++){
      /*---- posem la addr al buffer ----*/
      memcpy(&buffer[offset], &aux_rule->rule.addr.s_addr, sizeof(aux_rule->rule.addr.s_addr));
      offset += sizeof(aux_rule->rule.addr.s_addr);
      /*---- posem el flag de addr al buffer ----*/
      stshort(aux_rule->rule.src_dst_addr, &buffer[offset]);
      offset += sizeof(aux_rule->rule.src_dst_addr);
      /*---- posem la netmask al buffer ----*/
      stshort(aux_rule->rule.mask, &buffer[offset]);
      offset += sizeof(aux_rule->rule.mask);
      /*---- posem el flag del port al buffer ----*/
      stshort(aux_rule->rule.src_dst_port, &buffer[offset]);
      offset += sizeof(aux_rule->rule.src_dst_port);
      /*---- posem el numero de port al buffer ----*/
      stshort(aux_rule->rule.port, &buffer[offset]);
      offset += sizeof(aux_rule->rule.port);
      aux_rule = aux_rule->next_rule;
    }
    send(sock, buffer, offset, 0);
  }
}

void add_rule(int sock, struct FORWARD_chain *chain, char buffer[MAX_BUFF_SIZE]){
  int offset = 0;
  struct fw_rule *new_rule = malloc(sizeof(struct fw_rule *));
  /*---- llegim la addr ----*/
  memcpy(&new_rule->rule.addr.s_addr, buffer, sizeof(new_rule->rule.addr.s_addr));
  offset += sizeof(new_rule->rule.addr.s_addr);
  /*---- llegim el flag de la addr ----*/
  new_rule->rule.src_dst_addr = ldshort(&buffer[offset]);
  offset += sizeof(new_rule->rule.src_dst_addr);
  /*---- llegim la netmask----*/
  new_rule->rule.mask = ldshort(&buffer[offset]);
  offset += sizeof(new_rule->rule.mask);
  /*---- llegim el flag del port ----*/
  new_rule->rule.src_dst_port = ldshort(&buffer[offset]);
  offset += sizeof(new_rule->rule.src_dst_port);
  /*---- llegim el numero de port ----*/
  new_rule->rule.port = ldshort(&buffer[offset]);
  offset += sizeof(new_rule->rule.port);

  /*---- actualitzem la cadena ----*/

  new_rule->next_rule = NULL;
  /*---- si es la primera regla, l'afegim davant de tot ----*/
  if (chain->first_rule == NULL){
    chain->first_rule = new_rule;

  }
  /*---- sino, l'afegim al final ----*/
  else {
    struct fw_rule *iterator;
    iterator = chain->first_rule;
    while (iterator->next_rule !=NULL){
      iterator = iterator->next_rule;
    }
    iterator->next_rule = new_rule;
  }
  chain->num_rules += 1;
  unsigned short code = MSG_OK;
  offset = 0;
  stshort(code, buffer);
  offset += sizeof(code);
  send(sock, buffer, offset, 0);
}

void change_rule (int sock, struct FORWARD_chain *chain, char buffer[MAX_BUFF_SIZE]){
  unsigned short id;
  unsigned short opcode;
  id = ldshort(buffer);
  int offset = 0;
  offset += sizeof(id);
  if (id >= 1 && id <= chain->num_rules){
    struct fw_rule *aux_rule = malloc(sizeof(struct fw_rule *));
    aux_rule = chain->first_rule;
    if (id != 1){
      int i;
      for (i = 2; i <= id; i++){
        aux_rule = aux_rule->next_rule; ///
      }
    }

    printf("%s\n",inet_ntoa(aux_rule->rule.addr));
      /*---- llegim la addr ----*/
    memcpy(&aux_rule->rule.addr.s_addr, &buffer[offset], sizeof(aux_rule->rule.addr.s_addr));
    printf("%s\n",inet_ntoa(aux_rule->rule.addr));
    offset += sizeof(aux_rule->rule.addr.s_addr);
    /*---- llegim el flag de la addr ----*/
    aux_rule->rule.src_dst_addr = ldshort(&buffer[offset]);
    printf("%hu\n", aux_rule->rule.src_dst_addr);
    offset += sizeof(aux_rule->rule.src_dst_addr);
    /*---- llegim la netmask----*/
    aux_rule->rule.mask = ldshort(&buffer[offset]);
    printf("%hu\n", aux_rule->rule.mask);
    offset += sizeof(aux_rule->rule.mask);
    /*---- llegim el flag del port ----*/
    aux_rule->rule.src_dst_port = ldshort(&buffer[offset]);
    printf("%hu\n", aux_rule->rule.src_dst_port);
    offset += sizeof(aux_rule->rule.src_dst_port);
    /*---- llegim el numero de port ----*/
    aux_rule->rule.port = ldshort(&buffer[offset]);
    printf("%hu\n", aux_rule->rule.port);
    offset += sizeof(aux_rule->rule.port);
    opcode = MSG_OK;
    stshort(opcode, buffer);
    send(sock, buffer, sizeof(opcode), 0);
  }
  else {
    opcode = MSG_ERR;
    stshort(opcode, buffer);
    offset = 0;
    offset += sizeof(opcode);
    opcode = ERR_RULE;
    stshort(opcode, &buffer[offset]);
    offset += sizeof(opcode);
    send(sock, buffer, offset, 0);
  }
}

void delete_rule (int sock, struct FORWARD_chain *chain, char buffer[MAX_BUFF_SIZE]){
  unsigned short id;
  id = ldshort(buffer);
  unsigned short opcode;
  if (id >= 1 && id <= chain->num_rules){
    struct fw_rule *aux_rule, *rule_before, *rule_after; // conte rule i apuntadr a next_rule
    aux_rule = chain->first_rule; //es un apuntador
    if (id == 1){
    /*---- primera regla de la cadena ----*/

      if (aux_rule->next_rule == NULL){
      /*---- no apunta a cap regla ----*/
        chain->first_rule = NULL;
        free(aux_rule);
      }
      else {
      /*---- apunta a una altre regla ----*/
      rule_after =  aux_rule->next_rule; //sera el nou cap de la cadena
      chain->first_rule = rule_after;
      free(aux_rule);
      }
    }
    else if (id == chain->num_rules){
    /*---- ultima regla de la cadena, ens hem de moure fins al final de la cadena ----*/
      while (aux_rule->next_rule !=NULL){
      rule_before = aux_rule; //aixi tindrem la penultima regla aux1, i la ultima aux
      aux_rule = aux_rule->next_rule;
      }
    rule_before->next_rule = NULL;
    free(aux_rule);
    }
    else {
    /*---- regla entre el principi i el final ----*/
      int i;
      rule_after = aux_rule;
      for (i = 1; i < id + 1; i++){
        if (i == id - 1){
        /*---- regla que va abans ----*/
          rule_before = rule_after;
        }
        else if (i == id){
        /*---- regla a eliminar ----*/
        aux_rule = rule_after;
        }
        rule_after = rule_after->next_rule;
      }
      rule_before->next_rule = rule_after;
      free(aux_rule);
    }
    chain->num_rules -= 1;
    opcode = MSG_OK;
    stshort(opcode, buffer);
    send(sock, buffer, sizeof(opcode), 0);
  }
  else {
    opcode = MSG_ERR;
    stshort(opcode, buffer);
    int offset = 0;
    offset += sizeof(opcode);
    opcode = ERR_RULE;
    stshort(opcode, &buffer[offset]);
    offset += sizeof(opcode);
    send(sock, buffer, offset, 0);
  }


}

/**
* Function that deletes ALL the rules stored
* @param sock the communications socket
* @param chain the chain of rules
*/

void flush(int sock, struct FORWARD_chain *chain){
  struct fw_rule *aux_rule, *rule_before; // conte rule i apuntadr a next_rule
  unsigned short opcode;
  char buffer[MAX_BUFF_SIZE];
  memset(buffer, '\0', sizeof(buffer)); //inicialitzar a 0
  if (chain->first_rule != NULL){
    while (chain->first_rule != NULL){
      aux_rule = chain->first_rule;
      if (aux_rule->next_rule == NULL){ //nomes en tenim una
  	    chain->first_rule = NULL;
      }
      else{
  	    while(aux_rule->next_rule != NULL){ //ens movem a la ultima regla
          rule_before = aux_rule;
  	      aux_rule = aux_rule->next_rule;
        }
  	  rule_before->next_rule = NULL;
      }
      free(aux_rule);
   }
      chain->num_rules = 0;
      chain->first_rule = NULL;
    
    opcode = MSG_OK;
    stshort(opcode, buffer);
    send(sock, buffer, sizeof(opcode), 0);
  }
  else {
    opcode = MSG_ERR;
    stshort(opcode, buffer);
    int offset = 0;
    offset += sizeof(opcode);
    opcode = ERR_RULE;
    stshort(opcode, &buffer[offset]);
    offset += sizeof(opcode);
    send(sock, buffer, offset, 0);
  }


}

 /**
 * Receives and process the request from a client.
 * @param the socket connected to the client.
 * @param chain the chain with the filter rules.
 * @return 1 if the user has exit the client application therefore the
 * connection whith the client has to be closed. 0 if the user is still
 * interacting with the client application.
 */
int process_msg(int sock, struct FORWARD_chain *chain)
{
  unsigned short op_code;
  int finish = 0;

  char buffer[MAX_BUFF_SIZE];
  if (recv(sock, buffer, sizeof(buffer), 0) > 0){
    op_code = ldshort(buffer);
    printf("Opcode rebut client: %hu\n", op_code);
    int offset = sizeof(op_code);
    switch(op_code)
    {
      case MSG_HELLO:
        process_HELLO_msg(sock);
        break;
      case MSG_LIST:
        process_list_rules(sock, chain);
        break;
      case MSG_ADD:
        add_rule(sock, chain, &buffer[offset]);
        break;
      case MSG_CHANGE:
        change_rule(sock, chain, &buffer[offset]);
        break;
      case MSG_DELETE:
        delete_rule(sock, chain, &buffer[offset]);
        break;
      case MSG_FLUSH:
	      flush(sock, chain);
        break;
      case MSG_FINISH:
        close(sock);
        //TODO
        finish = 1;
        break;
      default:
        perror("Message code does not exist.\n");
    }
  }
    return finish;
}

 int main(int argc, char *argv[]){
  int port = getPort(argc, argv);
  int finish=0;
  struct FORWARD_chain chain;

  chain.num_rules=0;
  chain.first_rule=NULL;

  /*---- creem el socket del servidor ----*/
  int s,s2;
  s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s < 0){
    printf("\n Error : Could not create socket \n");
    return 1;
  }
  struct sockaddr_in server_addr;
  socklen_t server_addrlen = sizeof(server_addr);
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  server_addr.sin_addr.s_addr = INADDR_ANY;

  /*---- bind de la addr struct al socket ----*/
  if (bind(s, (struct sockaddr*)&server_addr, server_addrlen) < 0){
    printf("\n Error : Could not bind the socket \n");
    return 1;
  }
    while(1) {
    //TODO
      /*---- escoltem en el socket, amb un max de 10 request de connexio ----*/
      listen(s,MAX_QUEUED_CON);
      /*---- creem el socket per a la connexio amb el client ----*/
      s2 = accept(s, (struct sockaddr *) &server_addr, &server_addrlen);
      if (s2 < 0){
        printf("\n Error : accept failed \n");
        return 1;
      }
      int pid;
      pid = fork();
      if (pid < 0){
      /*---- error al crear el child ----*/
        printf("Error en crear el child");
        exit(1);
      }
      else if (pid == 0){
      /*---- child ----*/
        close(s);
        do {

        //TODO: finish = process_msg(....., &chain);

        finish = process_msg(s2,&chain);

      }while(!finish);
      close(s2);
      exit(0);

      }

      else {
      /*---- father ----*/
        close(s2);
      }
  }

  return 0;
 }
