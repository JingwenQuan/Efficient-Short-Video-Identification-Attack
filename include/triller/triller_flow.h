#ifndef TRILLER_FLOW_H
#define TRILLER_FLOW_H

#include "H12_flow.h"
#include "fingerprint/smp_fp.h"

class triller_flow_creator: public TLS_flow_creator
{
public:
    triller_flow_creator(packet_statistics_object_type type, std::string fname, 
                      std::string filter, int thre, int header): 
                      TLS_flow_creator(type, fname, filter, thre, header){}
                      
public:
    bool save_sorted_triller(std::string str_pcap, fp_file *lp_fp);
private:
    void find_max_match(int pos, stt_segment *lp_seg, std::vector<stt_segment> *lp_match);
    bool find_match(std::vector<stt_segment> *lp_match, uint32_t vid, int min_seg, int max_seg);

    void stat_seg_video();
private:
    std::vector<std::string> vct_msg_segment, vct_msg_video;
    std::vector<stt_seg_video> vct_cur_video, vct_fin_video;
};

#endif
