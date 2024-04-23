#include <iostream>
#include "triller/triller_flow.h"

using namespace std;

bool triller_flow_creator::save_sorted_triller(std::string str_pcap, fp_file *lp_fp)
{
    bool bout = false;
    char msg_buffer[1024];
    char buf[512];
    if(vct_ADU.size() > 0)
    {
        for(vector<stt_ADU_TLS>::iterator iter=vct_ADU.begin(); iter!=vct_ADU.end();)
        {
            if((*iter).s_estimate<5120)
                iter = vct_ADU.erase(iter);
            else
            {
                if(lp_fp)
                    lp_fp->match_segment((*iter).s_estimate, &((*iter).vct_match));
                ++iter;
            }
        }

        for(int i = 0; i<vct_ADU.size(); i++)
        {
            vct_ADU[i].st_seg.video_ID = 0;
            find_max_match(i, &(vct_ADU[i].st_seg), &(vct_ADU[i].vct_match));
        }
        stat_seg_video();

        string fname = str_pcap + ".triller.sorted.segment.csv";
        FILE* fp = fopen(fname.c_str(), "wt");
        if(fp)
        {
            fprintf(fp, "c_no,c_time,s_no,s_b_tm,s_e_tm,packet,,c_frag,c_len,,s_frag,s_len,s_first_TLS,s_TLS_max,s_TLS_min,s_estimate,,video,resolution,index,length,Diff.\n");
            for(vector<stt_ADU_TLS>::iterator iter=vct_ADU.begin(); iter!=vct_ADU.end(); ++iter)
            {
                fprintf(fp, "%d,%.4f,%d,%.4f,%.4f,%u,,%d,%d,,%d,%d,%d,%d,%d,%d,",
                        (*iter).c_no, (*iter).c_time, (*iter).s_no, (*iter).s_b_tm, (*iter).s_e_tm,
                        (*iter).s_pk_end-(*iter).s_pk_begin, 
                        (*iter).c_fragment, (*iter).c_length, 
                        (*iter).s_fragment, (*iter).s_length,
                        (*iter).s_first_frag, (*iter).s_max_flen, (*iter).s_min_flen, 
                        (*iter).s_estimate );

                if((*iter).st_seg.video_ID>0)
                {
                    if(lp_fp->get_video_info(buf, (*iter).st_seg.video_ID, (*iter).st_seg.reso_ID))
                    {
                        fprintf(fp, ",%s,%d,%d,%d", buf, (*iter).st_seg.seg_idx+1, (*iter).st_seg.len_seg, (*iter).s_estimate-(*iter).st_seg.len_seg);
                        sprintf(msg_buffer, ",%.4f,%.4F,%d,%d,%d,%s,%d", (*iter).s_b_tm, (*iter).s_e_tm, (*iter).s_estimate,
                                    (*iter).st_seg.len_seg, (*iter).s_estimate-(*iter).st_seg.len_seg,
                                    buf, (*iter).st_seg.seg_idx+1);
                        vct_msg_segment.push_back(msg_buffer);
                    }
                }
                else if((*iter).s_estimate>1048576)
                {
                    char msg[256], msg2[256];
                    if(lp_fp->match_fp2((*iter).s_estimate, buf, msg, msg2))
                    {
                        fprintf(fp, "%s", buf);
                        sprintf(msg_buffer, "##,%.4f,%.4F,%d,%s", (*iter).s_b_tm, (*iter).s_e_tm, (*iter).s_estimate, msg);
                        vct_msg_segment.push_back(msg_buffer);
                        sprintf(msg_buffer, "##,%.4f,%.4F,%d,%s", (*iter).s_b_tm, (*iter).s_e_tm, (*iter).s_estimate, msg2);
                        vct_msg_video.push_back(msg_buffer);
                    }
                }
                
                fprintf(fp, "\n");
            }
            fclose(fp);
            bout = true;
        }
        else
            cout << "open file error, file:" << fname << endl;

        fname = str_pcap + ".triller.match.seg.csv";
        fp = fopen(fname.c_str(), "wt");
        if(fp)
        {
            fprintf(fp, "type,tm_begin,tm_end,estimate,len,diff,video,reso,num_seg\n");
            for(vector<string>::iterator iter=vct_msg_segment.begin(); iter!=vct_msg_segment.end(); ++iter)
                fprintf(fp, "%s\n", (*iter).c_str());
            fclose(fp);
        }
        else
            cout << "open file error, file:" << fname << endl;

        fname = str_pcap + ".triller.video.csv";
        fp = fopen(fname.c_str(), "wt");
        if(fp)
        {
            fprintf(fp, "type,tm_begin,tm_end,len_TLS,len_video,diff,video\n");
            for(vector<string>::iterator iter=vct_msg_video.begin(); iter!=vct_msg_video.end(); ++iter)
                fprintf(fp, "%s\n", (*iter).c_str());
            fprintf(fp, "\n");
            fprintf(fp, ",tm_begin,tm_end,video,,len_data,k segments\n");
            for(vector<stt_seg_video>::iterator iter=vct_fin_video.begin(); iter!=vct_fin_video.end(); ++iter)
            {
                if(lp_fp->get_video_info(buf, (*iter).video_ID))
                    fprintf(fp, ",%.4f,%.4f,%s,,%d,%d\n", 
                            (*iter).tm_b, (*iter).tm_e, buf, (*iter).len_data, (*iter).num_seg);
            }
            fclose(fp);
        }
        else
            cout << "open file error, file:" << fname << endl;

    }    
    return bout;
}

void triller_flow_creator::stat_seg_video()
{
    stt_seg_video cur_v;
    for(vector<stt_ADU_TLS>::iterator iter=vct_ADU.begin(); iter!=vct_ADU.end(); ++iter)
    {
        if((*iter).st_seg.video_ID>0)
        {
            double time = (*iter).s_b_tm;
            bool bfind = false;
            for(vector<stt_seg_video>::iterator iter_cur = vct_cur_video.begin(); iter_cur!=vct_cur_video.end();)
            {
                if(time - (*iter_cur).tm_e > 50)
                {
                    if(vct_cur_video.size() == 1 &&  (*iter).st_seg.video_ID == (*iter_cur).video_ID)
                    {
                        (*iter_cur).len_data += (*iter).s_estimate;
                        (*iter_cur).tm_e = (*iter).s_e_tm;
                        (*iter_cur).num_seg ++;
                        bfind = true;
                        ++iter_cur;
                    }
                    else
                    {
                        vct_fin_video.push_back(*iter_cur);
                        iter_cur = vct_cur_video.erase(iter_cur);
                    }
                }
                else
                {
                    if((*iter).st_seg.video_ID == (*iter_cur).video_ID)
                    {
                        (*iter_cur).len_data += (*iter).s_estimate;
                        (*iter_cur).tm_e = (*iter).s_e_tm;
                        (*iter_cur).num_seg ++;
                        bfind = true;
                    }
                    ++iter_cur;
                }
            }
            if(!bfind)
            {
                cur_v.video_ID = (*iter).st_seg.video_ID;
                cur_v.tm_b = (*iter).s_b_tm;
                cur_v.tm_e = (*iter).s_e_tm;
                cur_v.len_data = (*iter).s_estimate;
                cur_v.num_seg = 1;
                vct_cur_video.push_back(cur_v);
            }
        }
    }
    for(vector<stt_seg_video>::iterator iter_cur = vct_cur_video.begin(); iter_cur!=vct_cur_video.end(); ++iter_cur)
    {
        vct_fin_video.push_back(*iter_cur);
    }
}

void triller_flow_creator::find_max_match(int pos, stt_segment *lp_seg, vector<stt_segment> *lp_match)
{
    int min_idx = pos - 12;
    if(min_idx < 0)
        min_idx = 0;
    int max_idx = pos + 12;
    if(max_idx >= vct_ADU.size())
        max_idx = vct_ADU.size() - 1;
    int cur_match = 0;

    for(vector<stt_segment>::iterator iter = lp_match->begin(); iter != lp_match->end(); ++iter)       
    {
        int imatch = 0, imatch_0 = 0, imatch_1 = 0, imatch_2 = 0;
        bool ret;

        for(int i = min_idx; i < pos; i++)
            if(find_match(&(vct_ADU[i].vct_match), (*iter).video_ID, (*iter).seg_idx, (*iter).seg_idx))
                imatch_0 ++;
        for(int i = pos + 1; i <= max_idx; i++)
            if(find_match(&(vct_ADU[i].vct_match), (*iter).video_ID, (*iter).seg_idx, (*iter).seg_idx))
                imatch_0 ++;
        for(int i = min_idx; i < pos; i++)
            if(find_match(&(vct_ADU[i].vct_match), (*iter).video_ID, (*iter).seg_idx-1, (*iter).seg_idx-1))
                imatch_1 ++;
        for(int i = pos + 1; i <= max_idx; i++)
            if(find_match(&(vct_ADU[i].vct_match), (*iter).video_ID, (*iter).seg_idx+1, (*iter).seg_idx+1))
                imatch_1 ++;
        if(imatch_1 > 0)
        {
            for(int i = min_idx; i < pos; i++)
                if(find_match(&(vct_ADU[i].vct_match), (*iter).video_ID, (*iter).seg_idx-2, (*iter).seg_idx-2))
                    imatch_2 ++;
            for(int i = pos + 1; i <= max_idx; i++)
                if(find_match(&(vct_ADU[i].vct_match), (*iter).video_ID, (*iter).seg_idx+2, (*iter).seg_idx+2))
                    imatch ++;
        }
        imatch = imatch_0 + imatch_1 + imatch_2;

        if(imatch >= 2 && imatch > cur_match)
        {
            cur_match = imatch;
            memcpy(lp_seg, &(*iter), sizeof(stt_segment));
        }
    }
}

bool triller_flow_creator::find_match(std::vector<stt_segment> *lp_match, uint32_t vid, int min_seg, int max_seg)
{
    bool bout = false;
    for(vector<stt_segment>::iterator iter = lp_match->begin(); iter != lp_match->end(); ++iter)       
    {
        if((*iter).video_ID==vid && (*iter).seg_idx >= min_seg && (*iter).seg_idx <= max_seg)
        {
            bout = true;
            break;
        }
    }
    return bout;
}
