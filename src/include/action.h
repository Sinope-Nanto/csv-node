#ifndef ACTION_H
#define ACTION_H

int csv_node_register(char* ip, int port, int id);
int csv_node_attestation(char* ip, int port);
int csv_node_update_ms(char* ip, int port);
int csv_node_update_cert(char* ip, int port);

#endif