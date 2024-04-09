#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int get_os_info(char* os_info, int buffer_len){
    FILE *fp = fopen("/proc/version", "r");
    int i = 0, num_space = 1;
    if(!fp)
        return 1;
    fgets(os_info, buffer_len, fp);
    while(os_info[i] != 0){
        if(os_info[i] == ' '){
            if(num_space == 3){
                os_info[i] = 0;
                break;
            }
            num_space++;
        }
        if(os_info[i] == '\n'){
            os_info[i] = 0;
            break;
        }
        i++;
    }
    fclose(fp);
    return 0;
}

int get_cpu_info(char* cpu_info, int buffer_len){
    FILE *fp = fopen("/proc/cpuinfo", "r");
    char* sys_info;
    int i = 0;
    if(!fp)
        return 1;
    while(!feof(fp)){
        memset(cpu_info, 0, buffer_len);
        fgets(cpu_info, buffer_len, fp);
        if(strstr(cpu_info, "model name")){
            fclose(fp);
            while(cpu_info[i] != '\0'){
                if(cpu_info[i] == '\n'){
                    cpu_info[i] = '\0';
                    break;
                }
                i++;
            }
            sys_info = strtok(cpu_info, ":");
            sys_info = strtok(NULL, ":");
            memcpy(cpu_info, sys_info + 1, 100);
            return 0;
            break;
        }
    }
    fclose(fp);
    return 1;
}

int get_cpu_manufacture(char* cpu_info, int buffer_len){
    FILE *fp = fopen("/proc/cpuinfo", "r");
    char* sys_info;
    int i = 0;
    if(!fp)
        return 1;
    while(!feof(fp)){
        memset(cpu_info, 0, buffer_len);
        fgets(cpu_info, buffer_len, fp);
        if(strstr(cpu_info, "vendor_id")){
            fclose(fp);
            while(cpu_info[i] != '\0'){
                if(cpu_info[i] == '\n'){
                    cpu_info[i] = '\0';
                    break;
                }
                i++;
            }
            sys_info = strtok(cpu_info, ":");
            sys_info = strtok(NULL, ":");
            memcpy(cpu_info, sys_info + 1, 100);
            return 0;
            break;
        }
    }
    fclose(fp);
    return 2;
}