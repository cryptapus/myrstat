#!/usr/bin/env python
"""
myrstat: plotting Myriad data.

  Copyright (c) 2017 cryptapus

  myrstat.py is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  This software is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with this software; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

"""

import matplotlib
matplotlib.use('Agg')
import configparser
from authproxy import AuthServiceProxy
from pylab import figure,legend,savefig
from matplotlib import ticker
import matplotlib.pyplot as plt
matplotlib.rcParams.update({'font.size': 10})
matplotlib.rc('xtick',labelsize=8)
matplotlib.rc('ytick',labelsize=8)

class myrstat(object):

    plotpath = None
    rpc = None
    block_window = None
    block_domain = None

    algos = []
    diffs = []
    heights = []
    versions = []
    bip9bits = []
    sizes = []
    times = []
    txnums = []

    blocklist = []

    algolist = ['sha256d','scrypt','groestl','yescrypt','argon2d']
    colorlist = ['#8ecf1d','#2db6db','#d7370c','#ffe21b','#8f3c85']
    figsize=(8,6)
    lw=2.0

    def __init__(self):
        # load config:
        Config = configparser.ConfigParser(allow_no_value = True)
        Config.read('config.cfg')
        network = Config.get('Global','network')
        rpcusername = Config.get(network,'rpcusername')
        rpcpassword = Config.get(network,'rpcpassword')
        rpcport = Config.getint(network,'rpcport')
        rpchostip = Config.get(network,'rpchostip')
        self.plotpath = str(Config.get(network,'htmlpath'))
        self.block_window = Config.getint(network,'block_window')
        self.block_domain = Config.getint(network,'block_domain')
        # set rpc:
        self.rpc = AuthServiceProxy('http://'+rpcusername+':'+rpcpassword+'@'+
                rpchostip+':'+str(rpcport))

    def run(self):
        self.getdata()
        self.getblockwindowlist()
        self.plotalgos()
        self.plotalgodiffs()
        self.plotversionma_algo()
        self.plotversionma()

    def get_moving_average_for_algo(self,algo,dlist,value,bip9=False):
        """Given an algo, give moving average percentage of value. Here bip9 is
        actually the bit signaling + 1"""
        # first get data for the algo:
        da = self.get_data_for_algo(algo,dlist,start=0)
        h = self.get_data_for_algo(algo,self.heights,start=0)
        pct = []
        # loop through data to get list that match targets:
        for i,ds in enumerate(da):
            (x,y) = self.get_data_for_window(h,da,h[i]-self.block_window,h[i])
            domain_length=len(x)
            c=0
            for tmp in y:
                if bip9:
                    # in this case, value is the bit we are seeking
                    tmp = bin(tmp)
                    if (tmp[0]!='-') and (len(tmp)>=value+2):
                        if tmp[-value]=='1':
                            c+=1
                else:
                    if tmp==value: c+=1
            if (domain_length==0):
                pct.append(0.)
            else:
                pct.append(float(c)/float(domain_length)*100.)
        return pct
    
    def get_moving_average(self,dlist,value,bip9=False):
        """Give moving average percentage of value. Here bip9 is actually the 
        bit signaling + 1"""
        # first get data for the algo:
        da = dlist
        h = self.heights
        pct = []
        # loop through data to get list that match targets:
        for i,ds in enumerate(da):
            (x,y) = self.get_data_for_window(h,da,h[i]-self.block_window,h[i])
            domain_length=len(x)
            c=0
            for tmp in y:
                if bip9:
                    # in this case, value is the bit we are seeking
                    tmp = bin(tmp)
                    if (tmp[0]!='-') and (len(tmp)>=value+2):
                        if tmp[-value]=='1':
                            c+=1
                else:
                    if tmp==value: c+=1
            if (domain_length==0):
                pct.append(0.)
            else:
                pct.append(float(c)/float(domain_length)*100.)
        return pct

    def getdata(self):
        """Get data via rpc."""
        info = self.rpc.getblockchaininfo()
        block_height = info['blocks']
        block_min = block_height - self.block_domain - self.block_window
        for bh in range(block_min,block_height+1,1):
            bhash = self.rpc.getblockhash(bh)
            block = self.rpc.getblock(bhash)
            self.algos.append(block['pow_algo'])
            self.diffs.append(block['difficulty'])
            self.heights.append(block['height'])
            self.versions.append((block['version'] & 255))
            self.sizes.append(block['size'])
            self.times.append(block['time'])
            self.txnums.append(len(block['tx']))
            if ((block['version'] & 0xFF000000) == 536870912):
                self.bip9bits.append((block['version'] & 0x000000FF))
            else:
                self.bip9bits.append(-1)

    def get_data_for_window(self,x,y,xmin,xmax):
        """Return a list of y values in x that are between xmin and xmax."""
        yi = []
        xi = []
        for i,tmp in enumerate(x):
            if (tmp>=xmin) and (tmp<=xmax):
                yi.append(y[i])
                xi.append(x[i])
        return (xi,yi)

    def moving_average_pct(self,raw,tgt):
        """generate a subset of data based on looking back by block_window."""
        d = []
        for i in range(self.block_window,
            self.block_domain+self.block_window+1):
            count=0.
            for k in range(0,self.block_window):
                if (raw[i-k]==tgt): count+=1
            d.append(count/self.block_window*100.)
        return d

    def getblockwindowlist(self):
        """Gets the block list for plotting."""
        for i in range(self.block_window,
            self.block_domain+self.block_window+1):
            self.blocklist.append(self.heights[i])

    def get_data_for_algo(self,algo,dlist,start=0):
        """Get the list corresponding to the algo."""
        d = []
        for i in range(start,self.block_domain+self.block_window+1):
            if (self.algos[i]==algo):
                d.append(dlist[i])
        return d

    def plotalgos(self):
        """plots aglos"""
        figure(figsize=self.figsize)
        for i, algo in enumerate(self.algolist):
            d = self.moving_average_pct(self.algos,algo)
            plt.plot(self.blocklist,d,'-',color=self.colorlist[i],label=algo,
                linewidth=self.lw)
            plt.grid('on')
            ax = plt.gca()
            ax.get_xaxis().set_minor_locator(ticker.AutoMinorLocator())
            ax.get_yaxis().set_minor_locator(ticker.AutoMinorLocator())
            ax.set_xlim([self.blocklist[0], self.blocklist[-1]])
            ax.grid(b=True, which='major', color='#a0a0a0', linestyle='-',
                linewidth=1.0)
            ax.grid(b=True, which='minor', color='#dcdcdc', linestyle='-',
                linewidth=0.5)
            ax.get_xaxis().get_major_formatter().set_scientific(False)
            ax.get_xaxis().get_major_formatter().set_useOffset(False)
            ax.set_xlabel('Block Number')
            ax.set_ylabel('% of Blocks')
        ax.set_title('Block % for Mining Algorithms')
        legend(self.algolist,loc=0,prop={'size':8})
        savefig(self.plotpath+'algohist.png',bbox_inches='tight')
    
    def plotversionma(self):
        """plots block versions"""
        figure(figsize=self.figsize)
        dm1 = self.get_moving_average(self.bip9bits,-1)
        d1 = self.get_moving_average(self.bip9bits,1,bip9=True)
        d2 = self.get_moving_average(self.bip9bits,2,bip9=True)
        d3 = self.get_moving_average(self.bip9bits,3,bip9=True)
        d5 = self.get_moving_average(self.bip9bits,5,bip9=True)
        d6 = self.get_moving_average(self.bip9bits,6,bip9=True)
        d7 = self.get_moving_average(self.bip9bits,7,bip9=True)
        # create an indicator line:
        di = []
        dibip = []
        for i in d1: di.append(75.)
        h = self.heights
        # block window:
        bw_calc = h[-1] - (h[-1] % self.block_window)
        bw_x = [bw_calc, bw_calc, 
                bw_calc-self.block_window, bw_calc-self.block_window,
                bw_calc]
        bw_y = [0, 100, 
                100, 0, 
                0]
        #plt.plot(h,dm1,'-',color='red',label='Legacy Blocks',
        #    linewidth=self.lw)
        #plt.plot(h,d1,'-',color='blue',label='CSV Blocks',
        #    linewidth=self.lw)
        #plt.plot(h,d2,'-',color='magenta',label='segwit Blocks',
        #    linewidth=self.lw)
        plt.plot(h,d3,'-',color='cyan',label='legbit Blocks',
            linewidth=self.lw)
        #plt.plot(h,d5,'-',color='red',label='reservealgo Blocks',
        #    linewidth=self.lw)
        #plt.plot(h,d6,'-',color='magenta',label='longblocks Blocks',
        #    linewidth=self.lw)
        plt.plot(h,d7,'-',color='blue',label='argon2d Blocks',
            linewidth=self.lw)
        plt.plot(h,di,'-.',color='green',label='BIP9 Activation Threshold',
            linewidth=self.lw)
        plt.plot(bw_x,bw_y,'-.',color='orange',label='Block Window',
            linewidth=self.lw)
        plt.grid('on')
        ax = plt.gca()
        ax.get_xaxis().set_minor_locator(ticker.AutoMinorLocator())
        ax.grid(b=True, which='major', color='#a0a0a0', linestyle='-',
            linewidth=1.0)
        ax.grid(b=True, which='minor', color='#dcdcdc', linestyle='-',
            linewidth=0.5)
        ax.get_xaxis().get_major_formatter().set_scientific(False)
        ax.get_xaxis().get_major_formatter().set_useOffset(False)
        ax.set_xlim([self.blocklist[0], self.blocklist[-1]])
        ax.set_ylim([-10., 110.])
        ax.set_ylabel('%')
        legend(loc=0,prop={'size':8})
        ax.set_title('Block Softforks')
        ax.set_xlabel('Block Number')
        savefig(self.plotpath+'versionma.png',bbox_inches='tight')

    def plotalgodiffs(self):
        figure(figsize=self.figsize)
        for i, algo in enumerate(self.algolist):
            d = self.get_data_for_algo(algo,self.diffs)
            h = self.get_data_for_algo(algo,self.heights)
            plt.subplot(len(self.algolist),1,i+1)
            plt.plot(h,d,'-',color=self.colorlist[i],label=algo,
                linewidth=self.lw)
            plt.grid('on')
            ax = plt.gca()
            ax.get_xaxis().set_minor_locator(ticker.AutoMinorLocator())
            ax.grid(b=True, which='major', color='#a0a0a0', linestyle='-',
                linewidth=1.0)
            ax.grid(b=True, which='minor', color='#dcdcdc', linestyle='-',
                linewidth=0.5)
            ax.get_xaxis().get_major_formatter().set_scientific(False)
            ax.get_xaxis().get_major_formatter().set_useOffset(False)
            ax.set_xlim([self.blocklist[0], self.blocklist[-1]])
            ax.set_ylabel(algo)
            if i==0: ax.set_title('Mining Difficulty')
            if not i==(len(self.algolist)-1):
                ax.xaxis.set_ticklabels([])
            else:
                ax.set_xlabel('Block Number')
        savefig(self.plotpath+'diffhist.png',bbox_inches='tight')

    def plotversionma_algo(self):
        figure(figsize=self.figsize)
        for i, algo in enumerate(self.algolist):
            dm1 = self.get_moving_average_for_algo(algo,self.bip9bits,-1)
            d1 = self.get_moving_average_for_algo(algo,self.bip9bits,1,
                    bip9=True)
            d2 = self.get_moving_average_for_algo(algo,self.bip9bits,2,
                    bip9=True)
            d3 = self.get_moving_average_for_algo(algo,self.bip9bits,3,
                    bip9=True)
            d5 = self.get_moving_average_for_algo(algo,self.bip9bits,5,
                    bip9=True)
            d6 = self.get_moving_average_for_algo(algo,self.bip9bits,6,
                    bip9=True)
            d7 = self.get_moving_average_for_algo(algo,self.bip9bits,7,
                    bip9=True)
            h = self.get_data_for_algo(algo,self.heights)
            plt.subplot(len(self.algolist),1,i+1)
            #plt.plot(h,dm1,'-',color='red',label='Legacy Blocks',
            #    linewidth=self.lw)
            #plt.plot(h,d1,'-',color='blue',label='CSV  Blocks',
            #    linewidth=self.lw)
            #plt.plot(h,d2,'-',color='magenta',label='segwit Blocks',
            #    linewidth=self.lw)
            plt.plot(h,d3,'-',color='cyan',label='legbit Blocks',
                linewidth=self.lw)
            #plt.plot(h,d5,'-',color='red',label='reservealgo Blocks',
            #    linewidth=self.lw)
            #plt.plot(h,d6,'-',color='magenta',label='longblocks Blocks',
            #    linewidth=self.lw)
            plt.plot(h,d7,'-',color='blue',label='argon2d Blocks',
                linewidth=self.lw)
            plt.grid('on')
            ax = plt.gca()
            ax.get_xaxis().set_minor_locator(ticker.AutoMinorLocator())
            ax.grid(b=True, which='major', color='#a0a0a0', linestyle='-',
                linewidth=1.0)
            ax.grid(b=True, which='minor', color='#dcdcdc', linestyle='-',
                linewidth=0.5)
            ax.get_xaxis().get_major_formatter().set_scientific(False)
            ax.get_xaxis().get_major_formatter().set_useOffset(False)
            ax.set_xlim([self.blocklist[0], self.blocklist[-1]])
            ax.set_ylim([-10., 110.])
            ax.set_ylabel(algo)
            legend(loc=3,prop={'size':8})
            if i==0: ax.set_title('Block Softfork %')
            if not i==(len(self.algolist)-1):
                ax.xaxis.set_ticklabels([])
            else:
                ax.set_xlabel('Block Number')
        savefig(self.plotpath+'algoversionma.png',bbox_inches='tight')
        

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Plot Myriad data.')
    m = myrstat()
    m.run()
