#ifndef GET_INFO_H
#define GET_INFO_H

int get_os_info(char* os_info, int buffer_len);
int get_cpu_info(char* cpu_info, int buffer_len);
int get_ip(const char* name, char* ip, int buffer_len);
int get_mac(const char* name, char* mac, int buffer_len);
int get_cpu_manufacture(char* cpu_info, int buffer_len);
int get_manufacture(char* buffer, int buffer_len);
int execmd(const char* cmd, char* result);

#endif