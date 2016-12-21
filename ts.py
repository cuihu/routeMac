import numpy as np
import matplotlib.pyplot as plt
import scapy.all as sc
import os
def anaIP(all):
	i = 1
	IP={}
	dst=[]
	src=[]
	for p in all:
		dst.append(p.sprintf("%IP.dst%"))
		src.append(p.sprintf("%IP.src%"))
	while i < len(dst):
		if IP.has_key(dst[i])==False:
			IP[dst[i]]=0
		if IP.has_key(src[i])==False:
			IP[src[i]]=0
		IP[dst[i]]+=1
		IP[src[i]]+=1
		i+=1
	return IP
def showIP(all):
	for p in all:
		print p.sprintf("%IP.dst%")

def showPlot(IP):
	x=[]
	y=[]
	for p in IP.keys():
		if IP[p]>300:
			x.append(p)
			y.append(IP[p])
	fig, ax = plt.subplots()
	width = 0.1       # the width of the bars
	n=len(y)
	ind=np.arange(n)
	rects1 = ax.bar(ind, y, width, color='r')
	ax.set_ylabel('Scores')
	ax.set_title('Scores by group and gender')
	ax.set_xticks(ind+width)
	ax.set_xticklabels(x)
	#ax.legend( (rects1[0], rects2[0]), ('Men', 'Women') )
	autolabel(ax,rects1)
	plt.show()


def autolabel(ax,rects):
    # attach some text labels
    for rect in rects:
        height = rect.get_height()
        ax.text(rect.get_x()+rect.get_width()/2., 1.05*height, '%d'%int(height),
                ha='center', va='bottom')

def anaTcp(all):
	Rc = {}
	tcp={}
	i = 0 
	tcp['sport']=''
	tcp['dport']=''
	tcp['flags']=''
	tcp['window']=''
	for p in all:
		if p.sprintf("%IP.proto%") == 'tcp' :
			tcp['sport']=p.sprintf("%TCP.sport%")
			tcp['dport']=p.sprintf("%TCP.dport%")
			tcp['flags']=p.sprintf("%TCP.flags%")
			tcp['window']=p.sprintf("%TCP.window%")
			print tcp
			if Rc.has_key(p.sprintf("%IP.src%"))==False:
				Rc[p.sprintf("%IP.src%")]={}
			Rc[p.sprintf("%IP.src%")][i]=tcp.copy()
			i+=1
		if i>100 :
			break 
	return Rc 

def showTcp(all):
	Rc = {}
	tcp = {}
	i = 0 
	for p in all:
		if p.sprintf("%IP.proto%") == 'tcp' :
			tcp['sport']=p.sprintf("%TCP.sport%")
			tcp['dport']=p.sprintf("%TCP.dport%")
			tcp['flags']=p.sprintf("%TCP.flags%")
			tcp['window']=p.sprintf("%TCP.window%")
			tcp['options']=p.sprintf("%TCP.options%")
			print tcp
			if Rc.has_key(p.sprintf("%IP.src%"))==False:
				Rc[p.sprintf("%IP.src%")]={}
			Rc[p.sprintf("%IP.src%")][i]=tcp.copy()
			i+=1
	return Rc

def RemData(filename):
	all=sc.rdpcap(filename)
	ip=anaIP(all)
	fileinfo=os.stat((filename))
	f=open('test.txt' ,'a')
	for p in ip:
		f.write(p+'   ')
		f.write('%s   ' %ip[p])
		f.write('%s\n' %fileinfo.st_atime)
	f.close()

