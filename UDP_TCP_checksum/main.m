//
//  main.m
//  UDP_TCP_checksum
//
//  Created by delims on 2019/12/13.
//  Copyright © 2019 delims. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "delimslib.h"

unsigned long checksum_calculate(const char *data_string, unsigned long from, unsigned long length, int checksum_index)
{
    unsigned long sum = 0;
      for (int i = 0; i < length; i += 4)
      {
          //不叠加校验和
          if (checksum_index > -1 && checksum_index == i) {
              continue;
          }
          unsigned long temp = 0;
          if ( length - i < 4) {
              temp = sub_string_to_long(data_string, (int)from + i, 2);
              sum += temp << 8;
          } else {
              temp = sub_string_to_long(data_string, (int)from + i, 4);
              sum += temp;
          }
      }
    return sum;
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // insert code here...
//        NSLog(@"Hello, World!\n");
    }
    
    const char *frame = "";
    
    if (strlen(frame) < 60) {
        printf("grab a TCP or UDP packet with wireshark ,copy hex stream and paste to 'frame' variable.\n");
        return 0;
    }

    unsigned long dest_mac   = sub_string_to_long(frame,  0, 12);
    unsigned long sour_mac   = sub_string_to_long(frame, 12, 12);
    unsigned long frame_type = sub_string_to_long(frame, 24,  4);
    
    printf("dest_mac: %lx\n",dest_mac);
    printf("sour_mac: %lx\n",sour_mac);
    printf("frame_type: %04lx\n\n",frame_type);
    
    unsigned int ip_offset = 24 + 4;
    unsigned long ip_version       = sub_string_to_long(frame, ip_offset +  0, 1);
    unsigned long ip_header_length = sub_string_to_long(frame, ip_offset +  1, 1);
    unsigned long diff_service     = sub_string_to_long(frame, ip_offset +  2, 2);
    unsigned long ip_tatol_length  = sub_string_to_long(frame, ip_offset +  4, 4);

    unsigned long identification   = sub_string_to_long(frame, ip_offset +  8, 4);
    unsigned long ip_flags         = sub_string_to_long(frame, ip_offset + 12, 1);
    unsigned long ip_frag_offset   = sub_string_to_long(frame, ip_offset + 12, 4) & 0B1111111111111;
    
    unsigned long ip_ttl           = sub_string_to_long(frame, ip_offset + 16, 2);
    unsigned long protocol         = sub_string_to_long(frame, ip_offset + 18, 2);
    unsigned long ip_header_check  = sub_string_to_long(frame, ip_offset + 20, 4);
    
    unsigned long ip_source        = sub_string_to_long(frame, ip_offset + 24, 8);
    
    unsigned long ip_destination   = sub_string_to_long(frame, ip_offset + 32, 8);
    
    printf("ip_version: %lx\n",ip_version);
    printf("ip_header_length: %lx\n",ip_header_length);
    printf("ip_tatol_length -> %lx : %lu\n\n", ip_tatol_length ,ip_tatol_length);

    printf("identification -> %lx : %lu\n", identification ,identification);
    
    int reserved_bit = (ip_flags & 0B1000) >> 3;
    int do_not_fragm = (ip_flags & 0B0100) >> 2;
    int more_fragmen = (ip_flags & 0B0010) >> 1;
    
    printf("reserved_bit: %i\n",reserved_bit);
    printf("do_not_fragm: %i\n",do_not_fragm);
    printf("more_fragmen: %i\n",more_fragmen);
    printf("ip_fragment_offset: %lu\n\n",ip_frag_offset);

    printf("ip_ttl -> %lu\n", ip_ttl);
    printf("protocol -> %lu\n" ,protocol);
    
    unsigned long ip_checksum = checksum_calculate(frame, ip_offset, ip_header_length * 4 * 2, 20);
    ip_checksum = (ip_checksum >> 16) + (ip_checksum & 0xffff);
    printf("ip_header_checksum -> %lx\n" ,ip_header_check);
    printf("calculate ip_checksum: %04lx\n\n",~ip_checksum & 0xffff);

    printf("ip_source: %lx -> %lu.%lu.%lu.%lu \n",ip_source,(ip_source & 0xff000000) >> 24, (ip_source & 0xff0000) >> 16, (ip_source & 0xff00) >> 8, ip_source & 0xff);
    printf("ip_dest: %lx -> %lu.%lu.%lu.%lu \n",ip_destination , (ip_destination & 0xff000000) >> 24, (ip_destination & 0xff0000) >> 16, (ip_destination & 0xff00) >> 8, ip_destination & 0xff);
    printf("differentiate_service: %lx\n",diff_service);
    
    int transmission_offset = ip_offset + (int)ip_header_length * 8;
    
    //calculate checksum
    unsigned long sum = 0;
    //ip address section of pseudo header
    sum += ip_source >> 16;
    sum += ip_source & 0xffff;
    sum += ip_destination >> 16;
    sum += ip_destination & 0xffff;
    
    if (protocol == 6) {
        unsigned long tcp_sour_port  = sub_string_to_long(frame, transmission_offset + 0 , 4);
        unsigned long tcp_dest_port  = sub_string_to_long(frame, transmission_offset + 4 , 4);
        unsigned long tcp_seq_number = sub_string_to_long(frame, transmission_offset + 8 , 8);
        unsigned long tcp_ack_number = sub_string_to_long(frame, transmission_offset + 16, 8);
        unsigned long tcp_header_len = sub_string_to_long(frame, transmission_offset + 24, 1);
        unsigned long tcp_flags      = sub_string_to_long(frame, transmission_offset + 26, 2);
        unsigned long tcp_window     = sub_string_to_long(frame, transmission_offset + 28, 4);
        unsigned long tcp_checksum   = sub_string_to_long(frame, transmission_offset + 32, 4);
        unsigned long tcp_length     = ip_tatol_length - ip_header_length * 4;
        unsigned long tcp_data_len   = tcp_length- tcp_header_len * 4;

        int URG = (tcp_flags & 0B100000) >> 5;
        int ACK = (tcp_flags & 0B010000) >> 4;
        int PSH = (tcp_flags & 0B001000) >> 3;
        int RST = (tcp_flags & 0B000100) >> 2;
        int SYN = (tcp_flags & 0B000010) >> 1;
        int FIN = (tcp_flags & 0B000001) >> 0;
        
        printf("tcp_sour_port -> %lx : %lu\n", tcp_sour_port ,tcp_sour_port);
        printf("tcp_dest_port -> %lx : %lu\n", tcp_dest_port ,tcp_dest_port);
        printf("tcp_seq_number -> %lx : %lu\n", tcp_seq_number ,tcp_seq_number);
        printf("tcp_ack_number -> %lx : %lu\n", tcp_ack_number ,tcp_ack_number);
        printf("tcp_header_length : %lu\n",tcp_header_len);
        printf("tcp_length : %lu\n",tcp_length);
        printf("tcp_data_length : %lu\n",tcp_data_len);

        printf("URG : %i\n",URG);
        printf("ACK : %i\n",ACK);
        printf("PSH : %i\n",PSH);
        printf("RST : %i\n",RST);
        printf("SYN : %i\n",SYN);
        printf("FIN : %i\n",FIN);
        
        printf("tcp_window -> %lx : %lu\n", tcp_window ,tcp_window);
        printf("tcp_checksum : %lx\n",tcp_checksum);
        
        //udp data segment
        sum += 6;
        sum += tcp_length;
        sum += checksum_calculate(frame, transmission_offset, tcp_length * 2, 32);
        printf("calculate checksum： %lx\n",(~((sum & 0xffff) + (sum >> 16))) & 0xffff);

        printf("\n");
        

    } else if (protocol == 17) {
        
        printf("\n");
        int udp_offset = transmission_offset;
        unsigned long udp_sour_port = sub_string_to_long(frame, udp_offset , 4);
        unsigned long udp_dest_port = sub_string_to_long(frame, udp_offset + 4 , 4);
        unsigned long udp_length    = sub_string_to_long(frame, udp_offset + 8 , 4);
        unsigned long udp_checksum  = sub_string_to_long(frame, udp_offset + 12, 4);

        printf("udp_sour_port -> %lx : %lu\n", udp_sour_port ,udp_sour_port);
        printf("udp_dest_port -> %lx : %lu\n", udp_dest_port ,udp_dest_port);

        printf("udp_length : %lu\n",udp_length);
        printf("udp_checksum : %lx\n",udp_checksum);

        sum += 17;
        sum += udp_length;
        sum += checksum_calculate(frame, transmission_offset, udp_length * 2, 12);
        printf("calculate checksum： %lx\n",(~((sum & 0xffff) + (sum >> 16))) & 0xffff);
        
        printf("\n");
    }
    
    

    printf("\n");

    
    return 0;
}


