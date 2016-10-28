/***************************************************************************
 *            fwServer.h
 *
 *  Copyright  2016  mc
 *  <mcarmen@<host>>
 ****************************************************************************/
 #include "common.h"

 #define MAX_QUEUED_CON 10 // Max number of connections queued



/**
 * Structures to implement the firewall rules
 * ==========================================
 */

 struct fw_rule
 {
    rule rule;
    struct fw_rule * next_rule;
 };

 struct FORWARD_chain
 {
   int num_rules;
   struct fw_rule * first_rule;
 };


/**
 * Returns the port specified as an application parameter or the default port
 * if no port has been specified.
 * @param argc the number of the application arguments.
 * @param an array with all the application arguments.
 * @return  the port number from the command line or the default port if
 * no port has been specified in the command line. Returns -1 if the application
 * has been called with the wrong parameters.
 */
int getPort(int argc, char* argv[]);


/**
 * Function that sends a HELLO_RP to the  client
 * @param sock the communications socket
 */
void process_HELLO_msg(int sock);

/**
* Function that returns to the client a list of the rules
* @param sock the communications socket
* @param chain the chain of rules
 */
void process_list_rules(int sock, struct FORWARD_chain *chain);


/**
* Function that recieves a buffer with the parameters
* of the rule the client wants to add
* @param sock the communications socket
* @param chain the chain of rules
* @param buffer the buffer with the parameters of the rule
*/
void add_rule(int sock, struct FORWARD_chain *chain, char buffer[MAX_BUFF_SIZE]);


/**
 * Receives and process the request from a client.
 * @param the socket connected to the client.
 * @param chain the chain with the filter rules.
 * @return 1 if the user has exit the client application therefore the
 * connection whith the client has to be closed. 0 if the user is still
 * interacting with the client application.
 */
int process_msg(int sock, struct FORWARD_chain *chain);

void change_rule (int sock, struct FORWARD_chain *chain, char buffer[MAX_BUFF_SIZE]);

void delete_rule (int sock, struct FORWARD_chain *chain, char buffer[MAX_BUFF_SIZE]);

void flush(int sock, struct FORWARD_chain *chain);
