#ifndef __CSV_VERIFY_H__
#define __CSV_VERIFY_H__

// 0返回值为验证通过
int csv_do_verify(char* report_hex, char* pub_x_hex, char* pub_y_hex, char* usr_id_hex, char* random_number_hex);

#endif