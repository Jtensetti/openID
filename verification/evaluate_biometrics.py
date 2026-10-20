"""Evaluate fixed thresholds against a private, held-out score set."""
import argparse
import csv
import json
import math
import os
import stat


def interval(errors,total):
    z=1.959963984540054;rate=errors/total;denominator=1+z*z/total
    center=(rate+z*z/(2*total))/denominator
    radius=z*math.sqrt(rate*(1-rate)/total+z*z/(4*total*total))/denominator
    return {'errors':errors,'samples':total,'rate':rate,'wilson95':[max(0,center-radius),min(1,center+radius)]}


def evaluate(records,face_threshold,pad_threshold):
    if not -1<=face_threshold<=1 or not 0<=pad_threshold<=1:raise ValueError('thresholds')
    counts={key:[0,0] for key in ('FMR','FNMR','APCER','BPCER')};seen=set();people={}
    for row in records:
        if set(row)!={'sample','subject','partition','kind','score'}:raise ValueError('columns')
        if not row['sample'] or row['sample'] in seen:raise ValueError('duplicate sample')
        seen.add(row['sample'])
        if len(seen)>1_000_000:raise ValueError('evaluation size')
        if not row['subject'] or row['partition'] not in ('calibration','evaluation'):raise ValueError('partition')
        if row['subject'] in people and people[row['subject']]!=row['partition']:raise ValueError('subject leakage between partitions')
        people[row['subject']]=row['partition']
        kind=row['kind'];score=float(row['score'])
        if not math.isfinite(score):raise ValueError('non-finite score')
        if kind in ('genuine','impostor'):
            if not -1<=score<=1:raise ValueError('face score')
            metric='FNMR' if kind=='genuine' else 'FMR';accepted=score>=face_threshold
            error=not accepted if kind=='genuine' else accepted
        elif kind in ('bona_fide','attack'):
            if not 0<=score<=1:raise ValueError('PAD score')
            metric='BPCER' if kind=='bona_fide' else 'APCER';accepted=score>=pad_threshold
            error=not accepted if kind=='bona_fide' else accepted
        else:raise ValueError('kind')
        if row['partition']=='evaluation':counts[metric][0]+=int(error);counts[metric][1]+=1
    if any(total==0 for errors,total in counts.values()):raise ValueError('all four evaluation classes required')
    return {'thresholds':{'face':face_threshold,'pad':pad_threshold},'metrics':{key:interval(*value) for key,value in counts.items()}}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--scores',required=True)
    parser.add_argument('--face-threshold',type=float,required=True);parser.add_argument('--pad-threshold',type=float,required=True)
    args=parser.parse_args();fd=os.open(args.scores,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode&0o077 or info.st_size>100_000_000:raise ValueError('private, bounded score file required')
        result=evaluate(csv.DictReader(stream),args.face_threshold,args.pad_threshold)
    print(json.dumps(result,allow_nan=False,indent=2))


if __name__=='__main__':main()
