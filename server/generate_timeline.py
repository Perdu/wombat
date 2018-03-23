#!/usr/bin/env python

import sys
from datetime import datetime, date, time, timedelta


class Report(object):
    def __init__(self, time, sensor_id, rssi, nb_frame):
        #(time_string, sensor_id, rssi, nb_frame) = report_string.split(',')
        self.time =  datetime.strptime(time, "%d %b %y %H:%M:%S:%f")  
        self.sensor_id = sensor_id
        self.rssi = float(rssi)
        self.nb_frame = int(nb_frame)
    def __repr__(self):
        return '{0}, {1}, {2}, {3}'.format(self.time, self.sensor_id,self.rssi,self.nb_frame)
    def get_time_interval(self):
        d = self.time
        k = d + timedelta(minutes=-(d.minute % QUERY_SERVER_TIMELINE_RESOLUTION)) 
        res =  datetime(k.year, k.month, k.day, k.hour, k.minute, 0)
        #print 'time interval', d, res
        return res


class Burst(object):
    def __init__(self):
        self.reports = []
    def __repr__(self):
        return self.reports[0]
    def add_report(self,report):
        self.reports.append(report)
    def get_start_time(self):
        
        try:
            return sorted(self.reports,key=lambda report: report.time)[0].time
        except IndexError:
            print datetime.fromtimestamp(0)
            return datetime.fromtimestamp(0)
        
my_reports= []

MAX_BURST_DURATION = 4
BATCH_SIZE = 2

def choose_area(batch):
    reports = []
    # put all the report of this batch in a single array
    for burst in batch:
        for r in burst.reports :
            reports.append(r)
    
    # search for the area  
    # based on the best rssi over the batch
    reports.sort(key = lambda x: x.rssi)
    print "reports[-1]" ,reports[-1]
    return reports[-1].sensor_id



def group_by_burst(reports):
    bursts = []
    cur_burst = Burst()
    for r in reports :
        print r
        if (r.time - cur_burst.get_start_time()).total_seconds() < MAX_BURST_DURATION :
            cur_burst.add_report(r)
        else :
            if len(cur_burst.reports) > 0 :
                bursts.append(cur_burst)
            cur_burst =  Burst()
            cur_burst.add_report(r)
         
    return bursts

def create_timeline(reports):
    #print reports
    timeline = []
    
    reports.sort(key = lambda x: x.time)
    bursts = group_by_burst(reports)
    
    #batchs = izip_longest(*[bursts[i::BATCH_SIZE] for i in range(BATCH_SIZE)]) 
    # group bursts by set (batch) of BATCH_SIZE
    batchs = []
    cur_batch = []
    i = 0
    for burst in bursts :
        cur_batch.append(burst)
        if i% BATCH_SIZE ==0:
            batchs.append(cur_batch)
            cur_batch = []
        i+=1
    if len(cur_batch) > 0 :
        batchs.append(cur_batch)

    # display for debug
    for batch in batchs :
        print "batch ---------------"
        for b in batch :
            print "burst ---------------"
            for r in b.reports :
                print r
    # create the timeline by choosing the area for each batch
    for batch in batchs :
        sensor_id = choose_area(batch) # choose the area
        t = batch[0].get_start_time() # reference time is the time of the first burst of the batch
        timeline += [[t.strftime("%d %b %y %H:%M"), sensor_id]]
    return timeline
        
        
        
            

if __name__ == "__main__":
    
    for l in open(sys.argv[1], 'r').readlines():
        #print l
        if len(l) > 1 :
            sensor_id, device_id, time_string, rssi, nb_frame, ssids = l.split(',')
            report = Report(time_string, sensor_id, rssi, nb_frame)
            my_reports.append(report)
            #print report
           

    timeline = create_timeline(my_reports)
    for item in timeline:
        print item
