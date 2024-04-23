#include <cstring>
#include <iostream>
#include <algorithm>
#include <time.h>

#include "fingerprint/smp_fp.h"

using namespace std;
const int max_line_length = 40960;

video_fp::video_fp(string id, string reso, int seg)
{
    str_ID = id;
    str_reso = reso;
    cntSeg = seg;
    vctSegLen.clear();
}

video_fp::~video_fp()
{
    vctSegLen.clear();
}

//===============================================================================================================================
//===============================================================================================================================
//===============================================================================================================================
fp_file::fp_file()
{
    vct_VFP.clear();
    vct_video.clear();
    vct_segment.clear();
}

fp_file::~fp_file()
{
    for(vector<video_fp *>::iterator iter=vct_VFP.begin(); iter!=vct_VFP.end(); ++iter)
    {
        video_fp * lpVFP = (*iter);
        if(lpVFP)
            delete lpVFP;
    }
    vct_VFP.clear();
    vct_video.clear();
    vct_segment.clear();
}

bool fp_file::loadfile(const char* fname, int type)
{
    bool bout = false;
    FILE *fp;
    char buffer[max_line_length];
    video_fp* lpVFP;
    str_fp = fname;

    fp = fopen(fname, "rt");
    if(fp){
        read_line(fp, buffer);
        while(read_line(fp, buffer)){
            lpVFP = getVideoFromLine(buffer);
            if(lpVFP)
            {
                if(lpVFP->check_video())
                {
                    vct_VFP.push_back(lpVFP);
                    if(type == 1)
                        make_fp(lpVFP);
                    bout = true;
                    //cout << lpVFP->get_message() << " ok." << endl;
                }
                else
                {
                    cout << lpVFP->get_message() << " ERROR!!!!!" <<endl;
                    delete lpVFP;
                }
            }
        }
        fclose(fp);
        cout << "Load " << vct_VFP.size() << " fingerprints" << endl;
    }
    else
        cout << "fingerprint file: " << fname << " error!" << endl;


    return bout;
}

bool fp_file::save_fp(const char* fname)
{
    bool bout = false;
    FILE* fp = fopen(fname, "wt");
    if(fp)
    {
        bout = true;
        fprintf(fp, "vid,resolution,num\n");
        for(vector<video_fp *>::iterator iter=vct_VFP.begin(); iter!=vct_VFP.end(); ++iter)
        {
            if((*iter)->get_seg_num()>0)
            {
                fprintf(fp, "%s,%s,%d,", (*iter)->get_video_ID().c_str(),
                                    (*iter)->get_video_reso().c_str(),
                                    (*iter)->get_seg_num()
                                    );
                vector<uint32_t> *lp_vct = (*iter)->get_segments();
                if(lp_vct)
                {
                    for(vector<uint32_t>::iterator iter_len = lp_vct->begin();
                                                iter_len != lp_vct->end();
                                                ++iter_len
                                                )
                        fprintf(fp, "%d,", *iter_len);
                }
                fprintf(fp, "\n");
            }
        }
        fclose(fp);
    }
    else
        cout << "file opening error: " << fname << endl;

    return bout;
}

bool fp_file::load_fp2(const char* fname)
{
    bool bout = false;
    FILE *fp;
    char buffer[max_line_length];
    char *point;
    string name;
    int length;
    stt_fp2 st_fp2;

    fp = fopen(fname, "rt");
    if(fp)
    {
        read_line(fp, buffer);
        while(read_line(fp, buffer))
        {
            point = strstr(buffer, ",");
            if(point)
            {
                point[0] = 0;
                name = buffer;
                length = atoi(point+1);
                if(length>0)
                {
                    st_fp2.vname = name;
                    st_fp2.length = length;
                    vct_fp2.push_back(st_fp2);
                    bout = true;
                }
            }
        }
        fclose(fp);
        cout << "Load " << vct_fp2.size() << " type 2 fingerprints" << endl;
    }
    return bout;
}

bool fp_file::read_line(FILE* fp, char* buf)
{
    int i = 0;
    char ch;

    buf[0] = 0;
    if(fp)
    {
        for(i=0; i<max_line_length; i++)
        {
            ch = (char)fgetc(fp);
            if( ch == EOF || ch == '\n')
            {
                buf[i] = 0;
                break;
            }
            buf[i]=ch;
        }
        if(ch == EOF && strlen(buf)<=0 )
            return false;
        else
            return true;
    }
    return false;
}

video_fp* fp_file::getVideoFromLine(char* buffer)
{
    char *point, *leftBuf;
    video_fp* lpVFP = NULL;
    string id, msg;
    int seg;

    leftBuf = buffer;
    //id
    point = strstr(leftBuf, ",");
    if(point)
    {
        point[0] = 0;
        id = leftBuf;
        leftBuf = point + 1;
        point = strstr(leftBuf, ",");
        if(point)
        {
            point[0] = 0;
            msg = leftBuf;
            leftBuf = point + 1;
            point = strstr(leftBuf, ",");
            if(point)
            {
                point[0] = 0;
                seg = atoi(leftBuf);
                leftBuf = point + 1;
                if(seg>0)
                {
                    lpVFP = new video_fp(id, msg, seg);
                    for(int i=0; i<seg; i++)      
                    {
                        point = strstr(leftBuf, ",");
                        if(point)
                        {
                            point[0] = 0;
                            int len = atoi(leftBuf);
                            if(len>0)
                                lpVFP->add_segment(len);
                            leftBuf = point + 1;
                        }
                        else if(i == seg-1)
                        {
                            int len = atoi(leftBuf);
                            if(len>0)
                                lpVFP->add_segment(len);
                        }
                    }              
                }
            }
        }

    }
    return lpVFP;
}

void fp_file::make_fp(video_fp* lp_vfp)
{
    string str_vid, str_reso;
    stt_segment st_seg;
    if(lp_vfp)
    {
        str_vid = lp_vfp->get_video_ID();
        str_reso = lp_vfp->get_video_reso();
        bool ret = get_video_reso(str_vid, str_reso, &st_seg);
        if(ret)
        {
            vector<uint32_t> *lp_seg = lp_vfp->get_segments();
            int idx = 0;
            for(vector<uint32_t>::iterator iter=lp_seg->begin(); iter!=lp_seg->end(); ++iter)
            {
                st_seg.seg_idx = idx;
                st_seg.len_seg = *iter;
                if(idx == 0)
                {
                    st_seg.len_min = *iter + 506 - 25;
                    st_seg.len_max = *iter + 506 + 25;
                    st_seg.len_TLS_payload = (*iter) + 508;
                }
                else
                {
                    st_seg.len_min = *iter + 886 - 25;
                    st_seg.len_max = *iter + 886 + 25;
                    st_seg.len_TLS_payload = (*iter) + 884;
                }
                vct_segment.push_back(st_seg);
                idx++;
            }
        }
    }
}

bool fp_file::get_video_reso(string vid, string reso, stt_segment *lp_seg)
{
    bool bout = false;

    stt_video_reso st_reso;
    stt_video st_video;
    bool bfind = false;
    for(vector<stt_video>::iterator iter=vct_video.begin(); iter!=vct_video.end(); ++iter)
    {
        if((*iter).video_name == vid)
        {
            bfind = true;

            st_reso.reso_info = reso;
            st_reso.reso_ID = (*iter).vct_resolution.size() + 1;
            (*iter).vct_resolution.push_back(st_reso);

            lp_seg->video_ID = (*iter).video_ID;
            lp_seg->reso_ID = st_reso.reso_ID;
            bout = true;
            break;
        }
    }
    if(!bfind)
    {
        st_video.video_name = vid;
        st_video.video_ID = vct_video.size() + 1;

        st_reso.reso_info = reso;
        st_reso.reso_ID = 1;
        st_video.vct_resolution.push_back(st_reso);

        vct_video.push_back(st_video);

        lp_seg->video_ID = st_video.video_ID;
        lp_seg->reso_ID = 1;
        bout = true;
    }

    return bout;
}

void fp_file::match_segment(int len, std::vector<stt_segment> *lp_seg)
{
    for(vector<stt_segment>::iterator iter=vct_segment.begin(); iter!=vct_segment.end(); ++iter)
    {
        /*
        if((*iter).len_min <= len && (*iter).len_max >= len)
            lp_seg->push_back(*iter);
        */     
        double min, max;
        min = (double)len - 7.83 - 8*2.59;
        max = (double)len - 7.83 + 8*2.59;
        if((*iter).len_TLS_payload >= min && (*iter).len_TLS_payload <= max)
            lp_seg->push_back(*iter);
        else
        {
            min = (double)len + 34.56 - 4*1.33;
            max = (double)len + 34.56 + 4*1.33;
            if((*iter).len_TLS_payload > min && (*iter).len_TLS_payload < max)
                lp_seg->push_back(*iter);
        }
    }
}

bool fp_file::get_video_info(char *lp_buf, uint32_t vid, uint16_t reso)
{
    bool bout = false;
    int vidx = vid-1, ridx = reso-1;
    if(vidx<0) vidx = 0;
    if(ridx<0) ridx = 0;

    if(vid <= vct_video.size())
    {
        if(reso <= vct_video[vidx].vct_resolution.size())
        {
            sprintf(lp_buf, "%s,%s", vct_video[vidx].video_name.c_str(), vct_video[vidx].vct_resolution[ridx].reso_info.c_str());
            bout = true;
        }
    }

    return bout;
}

bool fp_file::get_video_info(char *lp_buf, uint32_t vid)
{
    bool bout = false;
    int vidx = vid-1;
    if(vidx<0) vidx = 0;

    if(vid <= vct_video.size())
    {
        sprintf(lp_buf, "%s", vct_video[vidx].video_name.c_str());
        bout = true;
    }

    return bout;
}

bool fp_file::match_fp2(int len, char *buffer, char *msg, char *msg2)
{
    bool bout = false;
/*
    int min = 828-100;
    int max = 828+100;
    int min_diff = 1000;
    for(vector<stt_fp2>::iterator iter=vct_fp2.begin(); iter!=vct_fp2.end(); ++iter)
    {
        int diff = len - (*iter).length;
        if(diff >= min && diff <= max)
        {
            int cur = abs(diff - 828);
            if(cur < min_diff)
            {
                sprintf(buffer, "##,%s,,all,%d,%d", (*iter).vname.c_str(), (*iter).length, diff);
                sprintf(msg, "%d,%d,%s,,all", (*iter).length, diff, (*iter).vname.c_str());
                sprintf(msg2, "%d,%d,%s", (*iter).length, diff, (*iter).vname.c_str());
                min_diff = cur;
            }
            bout = true;
        }
    }
    return bout;
*/    
    int min1, min2, min3, min4, max1, max2, max3, max4;
    min1 = 16.22 - 1.47*4;
    max1 = 16.22 + 1.47*4;
    min2 = -22.35 - 0.48*4;
    max2 = -22.35 + 0.38*4;
    min3 = 242.62 - 0.48*4;
    max3 = 242.62 + 0.48*4;
    min4 = 280.8 - 0.8 * 4;
    max4 = 280.8 + 0.8 * 4;
    for(vector<stt_fp2>::iterator iter=vct_fp2.begin(); iter!=vct_fp2.end(); ++iter)
    {
        int diff = len - (*iter).length - 813;
        
        if( (diff>=min1 && diff<=max1) ||
            (diff>=min2 && diff<=max2) ||
            (diff>=min3 && diff<=max3) ||
            (diff>=min4 && diff<=max4) )
        {
            sprintf(buffer, "##,%s,,all,%d,%d", (*iter).vname.c_str(), (*iter).length, diff);
            sprintf(msg, "%d,%d,%s,,all", (*iter).length, diff, (*iter).vname.c_str());
            sprintf(msg2, "%d,%d,%s", (*iter).length, diff, (*iter).vname.c_str());
            bout = true;
            break;
        }
    }
    return bout;
}

void fp_file::check_same_fp()
{
    int cnt = vct_VFP.size();
    int num = 0;

    for(int i=0; i<cnt; i++)
    {
        for(int j = i+1; j<cnt; j++)
        {
            if(vct_VFP[i]->get_seg_num()>0 && comp_same((vct_VFP[i]), (vct_VFP[j])))
            {
                num ++;
                cout << num << " same fingerprint: " << vct_VFP[i]->get_video_ID() << "_" << vct_VFP[i]->get_video_reso() 
                     << ", " << vct_VFP[j]->get_video_ID() << "_" << vct_VFP[j]->get_video_reso() << endl;
                vct_VFP[j]->clear_segment();
            }
        }
    }
}

bool fp_file::comp_same(video_fp *lp_fp1, video_fp *lp_fp2)
{
    bool bout = false;
    uint32_t v1, v2;

    if(lp_fp1->get_seg_num() && lp_fp2->get_seg_num())
    {
        vector<uint32_t> *lp_seg1 = lp_fp1->get_segments();
        vector<uint32_t> *lp_seg2 = lp_fp2->get_segments();

        if(lp_seg1->size() == lp_seg2->size())
        {
            int cnt = lp_seg1->size();
            bout = true;
            for(int i=0; i<cnt; i++)
            {
                v1 = lp_seg1->at(i);
                v2 = lp_seg2->at(i);

                if(v1 != v2)
                {
                    bout = false;
                    break;
                }
            }
        }
    }
    return bout;
}
