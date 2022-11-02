#Author
#desc
#docstrings

#kommentare

#manual für installation und flags



################
#ROBUSTHEIT

#idee: für robustheit alle strings in lowercase vergleichen, falls die devs irgendwas ändern

#try catch debugmeldung

#Mögliche bug Ursache: Am anfang unsinn:
#['\x1b[H\x1b[JRun', 'Time:', '10', 'days,', '11', 'hours', 'and', '16', 'minutes']

#DATEN SO AUSLESEN, kein hardcode verwenden
#        try:
#            if len(tokens)>0:
#                for j in range(len(tokens)):
#                    if "irq" == tokens[j]:                                                                        
#                        irq = int(tokens[j-1][:-1])


#############################
#LESBARKEIT

#liste der Befehle die verwendet wurde für jeden Info Block + Zeile + größe des Blocks (auch wenn die nicht 100% übereinstimmt mit glogg)
#Im Zweifel kann man dann so überprüfen ob die Ausgabe legitim ist.




#################################
#TO DO FEATURES

#OUTPUT
#output sortieren -> active/cached, oder IPS/WAD, große Tabellen oben, kleine dinge unten

#debug log <-> try/catch error


#mehrere Files einlesen

#flags. 
    #cpu oder mem oder beides
    #-a . all flag. outputs die nur mit vorbedingungen ausgegeben werden auch ausgeben.
    #debug flag -> block xyz not found



#IPS engine und ips session: wenn eine einzelne IPS engine hoch ist und ein ein einzelner IPS Session wert viel mem verbruacht -> vermutlich gleiche PID
#IPS engine version

#(optinal. nicht klar wie viel man da rauslesen kann)ROLLUP   diagnose sys top-mem detail 

#Aus der Übersicht:
#memtotal, memfree, buffers, cache, active, inactive, shmem, slab
# unser top hat shared memory drin
#shared mem kann anon oder mapped sein

#sys top -> sortieren (vllt vorher addieren und mittelwert berechnen?)
#(optional) GNUPLOT für den top 5 Verbraucher, wenn es min 5 Datenpunkte gibt. Was kommt auf die Zeitachse? 

#sys top -> CPU Spalte 
#(optional) GNUPLOT für den top 5 Verbraucher, wenn es min 5 Datenpunkte gibt. Was kommt auf die Zeitachse? 
#https://stackoverflow.com/questions/8077099/short-guide-how-to-use-gnuplot-with-python


#meminfo slab
#Das offizielle Material sieht anders aus. Interna, S.11
#Uni Hannover S.55 -> Am Ende werden Pages reserviert. Es sei denn Fortinet hat den next level Scheiß am start.

#offset stimmt nicht in TAC_Logs_7510751 wird nicht die erste zeile gelesen

#File descriptors leak
#interna S.33

#Optimizations, Vergleich zu den default werten. interna S.36++

#IPS DEBUGGER, interna S.40++
#diag ips packet status -> #Packete die während conserve mode gedroppt worden sind.



#WAD DEBUGGER, interna S.44
# diagnose wad memory sum -> da gibts noch andere befehle diese tabelle auszulesen. welche? ab in die find_blocks()
#umrechnen der byes in megatbyte zum besseren auslesen.
# diagnose wad memory all -> debug mehrer wad worker

#CPU und Interrupts
#interna S.63

#Idee: Vorschläge ausgeben lassen. Beispiel: hoher cached wert und bei miglogd mem und disk erkannt -> abstellen
#vllt eine art abgleich von symptomen und gelösten tickets. 


#wad stats common | grep ses_ctx
#wad stats worker | grep active_tcp_port




# diag sys session list
# count of no_ofld_reason just like the gwy list for dirty sessions
# this should give an indication where the problem is


# diag sys proxy stats all
#was ist das?
#0.worker.times.lifetime : max 805548 us total 294051767 us avg 38859.75 us (7567 values)
#0.worker.times.avengine : max 805171 us total 291104084 us avg 38470.21 us (7567 values)
#0.worker.times.avengine_cb : max 311 us total 23083 us avg 3.05 us (7567 values)
#0.worker.times.fortiguard : max 0 us total 0 us avg 0.00 us (7567 values)










###########################################################
#Bugerkennung
##############################################################


#frees > allocs



####################################
#Bugs

#fragmentierter Memory Verbrauch für slabs sind noch nicht plausibel


######################################
######################################
                #CPU
######################################
#################################
#TO DO FEATURES


#get system performance
    #CPU states ausgeben
    #bei hohen IRQ oder SOFTIRQ -> proc/interrupts überprüfen
    
#proc/interrupts
#diagnose hardware sysinfo interrupt

    #nur als helferfunktion?
    #IPI0 bis IPI5 wichtig?
    #if bedingung err>0 -> Ausgeben!
    
#diag sys session list
#sessions nach und nach durchgehen
#was muss sonst noch in die tabelle?
#config system settings -> asymptotic enable?
#proto übersetzen für lesbarkeit -> eg. proto=6 -> TCP


#config system settings
#helferfunktion verschiedene checks werden vermutlich daten hier raus ziehen wollen.

#check sys vd 
#irgendwas mit fib. Welcher wert ist hier wichtig? 

####################################
#Bugs





#import numpy as np

import math
import traceback

from tabulate import tabulate
import sys
from collections import Counter
from _ast import Try


def sys_set(sys_set_start_line, lines, end_of_block):
    print("IPS SESSIONS")


    table_iter = 0
    data = []
    head = ["Name","Value"]
    for i in range(end_of_block-sys_set_start_line[0]-1):    
        tokens = lines[sys_set_start_line[0]+i].split()  
        try:
            if len(tokens)>0:
                      
                data.append([str(tokens[1])])
                data[table_iter].append(str(tokens[2]))
                table_iter = table_iter + 1

        except:
            print("jump! sys_settings")
            
    
    return data



def proxy_stats_all(proxy_table, lines, end_of_block,outputfile):
    print("### diagnose sys proxy stats all")

    
    dummy = 0
    
    elements = 0
    offset = 0    
    #For now - max - total
    for i in range(end_of_block-proxy_table):    
        tokens = lines[proxy_table + i].split()
        
        try:
            if len(tokens)>0:
                if tokens[0] == "statistics" and tokens[1] == "(manager)":
                    offset = i
                if len(tokens)>2:
                    #total not 0
                    if int(tokens[4]) != 0:
                        elements = elements + 1
        except:
            dummy = 0
    
    
    head = ["name", "now", "max", "total"]
    data = []
    for i in range(elements):    
        data.append(["-"])


    for i in range(elements):     
        for j in range(3):
            data[i].append("-")    
    



    k = 0
    for i in range(end_of_block-proxy_table):    
        tokens = lines[proxy_table+offset+i+1].split()
        try: 
            if len(tokens)>3:
                
                
                data[k][0] = tokens[0]
                
                if int(tokens[4]) == 0:
                    continue
                    

                for j in range(len(tokens)-1):
                    if tokens[j] == "now":
                        data[k][1] = tokens[j+1]
                
                    if tokens[j] == "max":
                        data[k][2] = tokens[j+1]                

                    if tokens[j] == "total":
                        data[k][3] = tokens[j+1]
            
                k = k +1            

                         
                
                    
        except:
            dummy = 0
            #print("jump! sys_proxy_table")

    
    tuples = []
    for i in range(elements-1):
            tuples.append((i,data[i][1]))


    #sort tuples
    data_sorted = sorted(tuples, key=lambda x: int(x[1]))
    data_sorted.reverse()
        

    #recreate the sorted data table
    data_sorted_table = []
    for i in range(elements-1):
        index = data_sorted[i][0]
        data_sorted_table.append(data[index])        

    
    
    

    #other
    elements2 = 0
    offset2 = 0
    for i in range(end_of_block-proxy_table):    
        tokens = lines[proxy_table + i].split()
        
        try:
            if len(tokens)>0:
                if tokens[0] == "statistics" and tokens[1] == "(manager)":
                    offset2 = i
                if len(tokens) == 2:
                    # not 0
                    if int(tokens[1]) != 0:
                        elements2 = elements2 + 1
        except:
            dummy = 0
    
    
    head2 = ["name", "value (#usages)"]
    data2 = []
    for i in range(elements2):    
        data2.append(["-"])


    for i in range(elements2):     
        for j in range(1):
            data2[i].append("-")       
    
    
    k2 = 0
    for i in range(end_of_block-proxy_table):    
        tokens = lines[proxy_table+offset2+i+1].split()
        try: 
            if len(tokens) == 2:
                
                
                data2[k2][0] = tokens[0]
                
                if int(tokens[1]) == 0:
                    continue
                    

                data2[k2][1] = tokens[1]
            
                k2 = k2 +1            

                         
                
                    
        except:
            dummy = 0
            #print("jump! sys_proxy_table")    
    
    

    tuples2 = []
    for i in range(elements2-1):
            tuples2.append((i,data2[i][1]))


    #sort tuples
    data_sorted2 = sorted(tuples2, key=lambda x: int(x[1]))
    data_sorted2.reverse()
        

    #recreate the sorted data table
    data_sorted_table2 = []
    for i in range(elements2-1):
        index = data_sorted2[i][0]
        data_sorted_table2.append(data2[index])       
    

    outputfile.write("\n")
    outputfile.write("\n")
    outputfile.write("### diagnose sys proxy stats all")
    outputfile.write("\n")
    outputfile.write("\n")        
    outputfile.write(tabulate(data_sorted_table,headers=head,tablefmt="grid"))
    outputfile.write("\n")  
    outputfile.write("\n")  
    outputfile.write("\n") 
    outputfile.write(tabulate(data_sorted_table2,headers=head2,tablefmt="grid"))
    outputfile.write("\n")  
    outputfile.write("\n")          

    return data

def wad_t(wad_table, lines, end_of_block,outputfile):
    print("### diagnose wad memory sum")


    elements = 0
    head = ["ID","allocs","frees","reallocs","avg_size","in_str","active","bytes","max","cmem object name"]   
    end_of_wad_block = 0 

    for i in range(end_of_block-wad_table):    
        tokens = lines[wad_table+i].split()
        try: 
            if len(tokens)>0:
                #print(tokens)
                
                if end_of_wad_block == 0:
                    elements = elements +1 
                    
                if tokens[0] == "id":
                    elements = 0 
                    offset = i
                    
                if tokens[0] == "implicit":
                    end_of_wad_block = 1                    
        except:
            print("jump! wad_table")
    

    print("elements " +str(elements))



    data = []
    for i in range(elements-1):    
        data.append(["-"])


    for i in range(elements-1):     
        for j in range(9):
            data[i].append("-")
    
    
    #fill matrix with data
    block_found = 0
    j = 0
    leak = ""
    alloc_bug = ""
    for i in range(end_of_block-wad_table):    
        tokens = lines[wad_table+i].split()
        try: 
            if len(tokens)>0:
                if tokens[0] == "id":
                    block_found = 1 
                    j = 0
                    continue
                    
            if len(tokens)>0 and block_found == 1:
                data[j][0] = tokens[0]                  #id
                data[j][1] = tokens[1]                  #allocs
                data[j][2] = tokens[2]                  #frees
                data[j][3] = tokens[3]                  #reallocs
                data[j][4] = tokens[4]                  #avg_size
                data[j][5] = tokens[5]                  #in_str
                data[j][6] = tokens[6]                  #active
                data[j][7] = tokens[7]                  #bytes
                data[j][8] = tokens[8]                  #max
                data[j][9] = tokens[9]                  #cmem object name
                
                #frees cannot exceed allocs
                
                if int(data[j][2]) > int(data[j][1]):
                    alloc_bug = data[j][9]
                
                #check for obvious memory leak
                if int(tokens[7]) < 0 or int(tokens[8]) < 0:
                    leak = tokens[9]
            j = j+1                        
        except:
            print("jump! wad_table")
  
    
    if leak == "":
        leak = "no obvious leak found, i.e. negative byte values"
    
    #create tuples used for sorting, first element is the key, the bytes column
    tuples = []
    for i in range(elements-1):
            tuples.append((i,data[i][7]))


    #sort tuples
    data_sorted = sorted(tuples, key=lambda x: int(x[1]))
    data_sorted.reverse()
    
    #recreate the sorted data table
    data_sorted_table = []
    for i in range(elements-1):
        index = data_sorted[i][0]
        data_sorted_table.append(data[index])    



    data_sorted = sorted(tuples, key=lambda x: int(x[1]))
    data_sorted.reverse()
    


    outputfile.write("### diagnose wad memory sum")
    outputfile.write("\n")
    outputfile.write("\n")        
    outputfile.write(tabulate(data_sorted_table,headers=head,tablefmt="grid"))
    outputfile.write("\n")
    outputfile.write("\n")    
    outputfile.write("leak found: "+ leak)       
    outputfile.write("\n")  
    outputfile.write("\n")      
    
    if alloc_bug != "":
            outputfile.write("\n")    
            outputfile.write("Wrong allocation found at: "+ leak)       
            outputfile.write("\n")  
            outputfile.write("check for more inconsistencies")    
            outputfile.write("\n")  
    return data_sorted_table


def wad_all(wad_table, lines, end_of_block,outputfile):
    print("### diagnose wad memory all")


    #******* [type=worker pid=304 idx=0] *******
    
    elements = 0
    head = ["ID","allocs","frees","reallocs","avg_size","in_str","active","bytes","max","cmem object name"]   
    end_of_wad_block = 0 
    

    PID = []
    blocks = []
    
    print(wad_table)
    print(end_of_block)    
    print(end_of_block-wad_table)
    
    for i in range(end_of_block-wad_table):    
        tokens = lines[wad_table+i].split()
        try: 
            if len(tokens)>0:
                #print(tokens)
                
                if tokens[2].split("=")[0] == "pid":
                    PID.append(tokens[2].split("=")[1])
                 
                if end_of_wad_block == 0:
                    elements = elements +1 
                    
                if tokens[0] == "id":
                    elements = 0 
                    offset = i
                    blocks.append(i)
                                      
        except:
            print("jump! wad_table_all")
    

    print("elements " +str(elements))


    print("PID " +str(PID))
    print("\n")
    print("\n")
    print("blocks " + str(blocks))

    data = []
    for i in range(elements-1):    
        data.append(["-"])


    for i in range(elements-1):     
        for j in range(9):
            data[i].append("-")
    
    
    #fill matrix with data
    block_found = 0
    j = 0
    leak = ""
    alloc_bug = ""
    for i in range(end_of_block-wad_table):    
        tokens = lines[wad_table+i].split()
        try: 
            if len(tokens)>0:
                if tokens[0] == "id":
                    block_found = 1 
                    j = 0
                    continue
                    
            if len(tokens)>0 and block_found == 1:
                data[j][0] = tokens[0]                  #id
                data[j][1] = tokens[1]                  #allocs
                data[j][2] = tokens[2]                  #frees
                data[j][3] = tokens[3]                  #reallocs
                data[j][4] = tokens[4]                  #avg_size
                data[j][5] = tokens[5]                  #in_str
                data[j][6] = tokens[6]                  #active
                data[j][7] = tokens[7]                  #bytes
                data[j][8] = tokens[8]                  #max
                data[j][9] = tokens[9]                  #cmem object name
                
                #frees cannot exceed allocs
                
                if int(data[j][2]) > int(data[j][1]):
                    alloc_bug = data[j][9]
                
                #check for obvious memory leak
                if int(tokens[7]) < 0 or int(tokens[8]) < 0:
                    leak = tokens[9]
            j = j+1                        
        except:
            print("jump! wad_table")
  
    
    if leak == "":
        leak = "no obvious leak found, i.e. negative byte values"
    
    #create tuples used for sorting, first element is the key, the bytes column
    tuples = []
    for i in range(elements-1):
            tuples.append((i,data[i][7]))


    #sort tuples
    data_sorted = sorted(tuples, key=lambda x: int(x[1]))
    data_sorted.reverse()
    
    #recreate the sorted data table
    data_sorted_table = []
    for i in range(elements-1):
        index = data_sorted[i][0]
        data_sorted_table.append(data[index])    



    data_sorted = sorted(tuples, key=lambda x: int(x[1]))
    data_sorted.reverse()
    


    outputfile.write("### diagnose wad memory all")
    outputfile.write("\n")
    outputfile.write("\n")        
    outputfile.write(tabulate(data_sorted_table,headers=head,tablefmt="grid"))
    outputfile.write("\n")
    outputfile.write("\n")    
    outputfile.write("leak found: "+ leak)       
    outputfile.write("\n")  
    outputfile.write("\n")      
    
    if alloc_bug != "":
            outputfile.write("\n")    
            outputfile.write("Wrong allocation found at: "+ leak)       
            outputfile.write("\n")  
            outputfile.write("check for more inconsistencies")    
            outputfile.write("\n")  
    return data_sorted_table





def miglogd(mig_start_line, lines, end_of_block,outputfile):
    print("MIGLOGD")
    print(lines[mig_start_line[0]])
    outputfile.write("\n") 
    outputfile.write("\n") 
    outputfile.write("### diagnose test application miglogd 6")
    outputfile.write("\n") 
    outputfile.write("\n") 
    
    for i in range(end_of_block-mig_start_line[0]-1):    
        tokens = lines[mig_start_line[0]+i].split()  
        try:
            if len(tokens)>0:
                if "mem" in tokens[0]:
                        
                        outputfile.write("\n")    
                        outputfile.write(lines[mig_start_line[0]+i]) 
                        outputfile.write("\n")   
                        outputfile.write("\n")         
                                                
        except:
            print("jump! miglogd")

def ips_s(ips_start_line, lines, end_of_block,outputfile):
    print("IPS SESSIONS")
    print(lines[ips_start_line[0]])
    


    table_iter = 0
    data = []
    head = ["Name","Value"]
    for i in range(end_of_block-ips_start_line[0]-1):    
        tokens = lines[ips_start_line[0]+i].split()  
        try:
            if len(tokens)>0:
                      
                if tokens[0] == "memory" and tokens[1] == "capacity":
                    data.append([str(tokens[0])+ " "+ str(tokens[1])])
                    data[table_iter].append(str(tokens[2]))
                    table_iter = table_iter + 1

                if tokens[0] == "memory" and tokens[1] == "used":
                    data.append([str(tokens[0])+ " "+ str(tokens[1])])
                    data[table_iter].append(str(tokens[2]))
                    table_iter = table_iter + 1
                    
                if tokens[0] == "session" and tokens[1] == "in-use":
                    data.append([str(tokens[0])+ " "+ str(tokens[1])])
                    data[table_iter].append(str(tokens[2]))
                    table_iter = table_iter + 1                    

                if tokens[1] == "pkt" and tokens[2] == "loss:":
                    data.append([str(tokens[1])+ " "+ str(tokens[2])])
                    data[table_iter].append(str(tokens[3]))
                    table_iter = table_iter + 1


        except:
            print("jump! ips_s")
            
    
    outputfile.write("### get ips session")
    outputfile.write("\n")    
    outputfile.write(tabulate(data,headers=head,tablefmt="grid"))
    outputfile.write("\n")   
    outputfile.write("\n")     
    outputfile.write("\n")      
           
            
            

def slab(slab_start_line, lines, end_of_block,outputfile):
    print("### diagnose hardware sysinfo slab")
    print(lines[slab_start_line[0]])
    
    MB = 1000000
    offset = 0
    elements = 0
    slab_block_found = 0
    head = ["Process", "active Objects", "number of Objects", "Object Size", "Objects per Slab", "pages per slab", ":", "tunables", "limit", "batch count", "shared count", ":", "slabdata", "active slabs", "number of slabs", "shared availabe", "min mem usage (MB)", "mem usage with int. fragmentation"]   

    for i in range(end_of_block-slab_start_line[0]):    
        tokens = lines[slab_start_line[0]+i].split()
        if slab_block_found == 0:
            offset = offset + 1       
        try:
            if len(tokens)>1:
                
                if tokens[7] == "tunables":
                    slab_block_found = 1
                    elements = elements + 1 

        except:
            print("jump! slab")        

        

    offset = offset -1


    data = []
    for i in range(elements):    
        data.append(["-"])


    for i in range(elements):     
        for j in range(17):
            data[i].append("-")
    
    


    for i in range(elements):
        #Blockstart + n-th Block Offset + RunTime Lines Offset(2)
        #print(i)
        
        tokens = lines[slab_start_line[0] + offset + i].split()
        #print(tokens)
        for j in range(16):
            data[i][j] = tokens[j]
        data[i][16] = int(data[i][2]) * int(data[i][3])/MB  
        
        
        #BUGGED! THESE NUMBERS DONT ADD UP, IT SHOULD ALWAYS BE GREATER THAN THE MIN MEM REQUIRED
        #DOES THE BUDDY ALWAYS ALLOCATE 4kb?
        #CHECK PAGES PER SLAB COLUM IN THE COMMAND OUTPUT
        #not sure if that is correct, this number is based on my understanding of the buddy allocator system
        #elements per 4k page
        elem_page = math.floor((int(data[i][5])*4096)/int(data[i][3]))   
        #print("Runde " + str(i) + "   " + str((int(data[i][5])*4096)/int(data[i][3]))+ "    floor: " + str(elem_page))

        if elem_page == 0:
            data[i][17] = 0        
        else:
            data[i][17] = int(int(data[i][2])/elem_page * 4096)/MB           

    
    #print("len data " + str(len(data)))
    
    data_tuple = []
    for i in range(elements):
        data_tuple.append((i,data[i][16]))
    
    #print(data_tuple)
    
    data_sorted = sorted(data_tuple, key=lambda x: int(x[1]))
    data_sorted.reverse()
    
    
    data_sorted_table = []
    for i in range(elements):
        index = data_sorted[i][0]
        data_sorted_table.append(data[index])    
    


    outputfile.write("### diagnose hardware sysinfo slab")
    outputfile.write("\n")    
    outputfile.write(tabulate(data_sorted_table,headers=head,tablefmt="grid"))
    outputfile.write("\n")   
    outputfile.write("\n")     
    outputfile.write("\n")      




def mem_overview(mem_start_line, lines, end_of_block,outputfile):
    print("MEMORY OVERVIEW")
   
    
    usefull_values = 8
    
    data = []
    for i in range(usefull_values):    
        data.append(["dummy"])


    for i in range(usefull_values):     
        for j in range(1):
            data[i].append("dummy")

    
    
    
    data_full = []
    for i in range(32):    
        data_full.append(["dummy"])

    for i in range(32):     
        for j in range(1):
            data_full[i].append(["dummy"])   
    
    
    table_iter = 0
    j = 0
    for i in range(end_of_block-mem_start_line[0]-1):    
        tokens = lines[mem_start_line[0]+i].split()  

        if len(tokens)>0:

            if tokens[0] == "MemTotal:":
                data[table_iter][0] = "MemTotal"
                data[table_iter][1] = str(tokens[1]) + " " + str(tokens[2])
                Memtotal = tokens[1]
                table_iter = table_iter + 1
                j = 0


            try:
                data_full[j][0] = str(tokens[0])
                data_full[j][1] = str(tokens[1])
                j = j +1          
            except:
                print("jump! mem")
                        
             
            if tokens[0] == "MemFree:":
                data[table_iter][0] = "MemFree"
                data[table_iter][1] = str(tokens[1]) + " " + str(tokens[2])
                Memfree = tokens[1]
                table_iter = table_iter + 1             

            if tokens[0] == "Buffers:":
                data[table_iter][0] = "Buffer"
                data[table_iter][1] = str(tokens[1]) + " " + str(tokens[2])
                table_iter = table_iter + 1             
   
            if tokens[0] == "Cached:":
                data[table_iter][0] = "Cached"
                data[table_iter][1] = str(tokens[1]) + " " + str(tokens[2])
                table_iter = table_iter + 1                         
   
            if tokens[0] == "Active:":
                data[table_iter][0] = "Active"
                data[table_iter][1] = str(tokens[1]) + " " + str(tokens[2])
                table_iter = table_iter + 1             
   
            if tokens[0] == "Inactive:":
                data[table_iter][0] = "Inactive"
                data[table_iter][1] = str(tokens[1]) + " " + str(tokens[2])
                table_iter = table_iter + 1             
                   
            if tokens[0] == "Shmem:":
                data[table_iter][0] = "Shmem"
                data[table_iter][1] = str(tokens[1]) + " " + str(tokens[2])
                table_iter = table_iter + 1                   

            if tokens[0] == "Slab:":
                data[table_iter][0] = "Slab"
                data[table_iter][1] = str(tokens[1]) + " " + str(tokens[2])
                table_iter = table_iter + 1           
       
        
            
    head = ["Name", "Size"]          
    
    outputfile.write("### diagnose hardware sysinfo memory")
    outputfile.write("\n")    
    outputfile.write(tabulate(data,headers=head,tablefmt="grid"))
    outputfile.write("\n") 
    outputfile.write("Free Memory: " + str(int(Memfree)/int(Memtotal)*100)+"%")       
    outputfile.write("\n")  
    outputfile.write("\n")
    outputfile.write("\n")  
    outputfile.write("\n")
    
    return data_full
    
    
    
            
    
def shm(shm_occurances, lines, end_of_block, outputfile):
    print("CALCULATING USAGE OF /DEV/SHM")

    MB = 1000000    
    shm_tuples = []
    #name im letzten token
    #größe im vorletzten token
    for i in range(end_of_block-shm_occurances[0]-1):   
        tokens = lines[shm_occurances[0]+i+1].split()
        try:
            if len(tokens)>0:
                size = int(tokens[9])/MB
                name = tokens[10]
                shm_tuples.append((name,size))
        except:
            print("jump! tmp")
        
    #print(shm_tuples[1])        
    
    size_numbered_processes = 0   #gumball Processes 
    cmdb_short = []
    for i in range(len(shm_tuples)):
        if(shm_tuples[i][0].isnumeric()) == True:
            #print(cmdb_tuples[i][0])
            size_numbered_processes = size_numbered_processes + int(shm_tuples[i][1])
        if(shm_tuples[i][0].isnumeric()) == False: 
              cmdb_short.append(shm_tuples[i])

    #cmdb_short.append(("numbered_processes", int(size_numbered_processes))) 
    cmdb_sorted = sorted(cmdb_short, key=lambda x: float(x[1]))
    cmdb_sorted.reverse()
    
    data = []
    for i in range(len(cmdb_sorted)):    
        data.append(["dummy"])


    for i in range(len(cmdb_sorted)):     
        for j in range(1):
            data[i].append("dummy")
    

    for i in range(len(cmdb_sorted)):
        data[i][0] = cmdb_sorted[i][0]
        data[i][1] = cmdb_sorted[i][1]            
        
            
    head = ["Name", "Size (MB)"]          
    #print(tabulate(data,headers=head,tablefmt="grid"))  

    outputfile.write("#### /DEV/SHM")
    outputfile.write("\n")    
    outputfile.write(tabulate(data,headers=head,tablefmt="grid"))
    outputfile.write("\n")   
    outputfile.write("\n")  
    outputfile.write("\n")  

def tmp(tmp_occurances, lines, end_of_block,outputfile):
    print("CALCULATING USAGE OF /DEV/TMP")

    MB = 1000000    
    tmp_tuples = []
    #name im letzten token
    #größe im vorletzten token
    for i in range(end_of_block-tmp_occurances[0]-1):   
        tokens = lines[tmp_occurances[0]+i+1].split()
        try:
            if len(tokens)>0:
                size = int(tokens[9])
                if size != 0:
                    size = int(tokens[9])/MB
                name = tokens[10]
                tmp_tuples.append((name,size))
        except:
            print("jump! tmp")
        
    #print(tmp_tuples[1])        
    
    size_numbered_processes = 0   #gumball Processes 
    cmdb_short = []
    for i in range(len(tmp_tuples)):
        if(tmp_tuples[i][0].isnumeric()) == True:
            #print(cmdb_tuples[i][0])
            size_numbered_processes = size_numbered_processes + int(tmp_tuples[i][1])
        if(tmp_tuples[i][0].isnumeric()) == False: 
              cmdb_short.append(tmp_tuples[i])

    #cmdb_short.append(("numbered_processes", int(size_numbered_processes))) 
    cmdb_sorted = sorted(cmdb_short, key=lambda x: float(x[1]))
    cmdb_sorted.reverse()
    
    data = []
    for i in range(len(cmdb_sorted)):    
        data.append(["dummy"])


    for i in range(len(cmdb_sorted)):     
        for j in range(1):
            data[i].append("dummy")
    

    for i in range(len(cmdb_sorted)):
        data[i][0] = cmdb_sorted[i][0]
        data[i][1] = cmdb_sorted[i][1]            
        
            
    head = ["Name", "Size (MB)"]          
    #print(tabulate(data,headers=head,tablefmt="grid"))  


    outputfile.write("###  /DEV/TMP")
    outputfile.write("\n")    
    outputfile.write(tabulate(data,headers=head,tablefmt="grid"))
    outputfile.write("\n")   
    outputfile.write("\n")  
    outputfile.write("\n")  
    

def cmdb(cmdb_occurances, lines, end_of_block,outputfile):
    print("CALCULATING USAGE OF /DEV/CMDB")

    MB = 1000000
    cmdb_tuples = []
    #name im letzten token
    #größe im vorletzten token
    for i in range(end_of_block-cmdb_occurances[0]-1):   
        tokens = lines[cmdb_occurances[0]+i+1].split()
        try:
            if len(tokens)>0:
                size = float(tokens[9])/MB
                name = tokens[10]
                cmdb_tuples.append((name,size))
        except:
            print("jump! cmdb")
        
    print(cmdb_tuples[1])        
    
    size_numbered_processes = 0   #gumball Processes 
    cmdb_short = []
    for i in range(len(cmdb_tuples)):
        if(cmdb_tuples[i][0].isnumeric()) == True:
            size_numbered_processes = size_numbered_processes + float(cmdb_tuples[i][1])
            
        if(cmdb_tuples[i][0].isnumeric()) == False: 
              cmdb_short.append(cmdb_tuples[i])

    cmdb_short.append(("numbered_processes", float(size_numbered_processes))) 
    cmdb_sorted = sorted(cmdb_short, key=lambda x: float(x[1]))
    cmdb_sorted.reverse()
    
    data = []
    for i in range(len(cmdb_sorted)):    
        data.append(["dummy"])


    for i in range(len(cmdb_sorted)):     
        for j in range(1):
            data[i].append("dummy")
    

    for i in range(len(cmdb_sorted)):
        data[i][0] = cmdb_sorted[i][0]
        data[i][1] = cmdb_sorted[i][1]            
        
            
    head = ["Name", "Size (MB)"]          

    outputfile.write("###  /DEV/CMDB")
    outputfile.write("\n")    
    outputfile.write(tabulate(data,headers=head,tablefmt="grid"))
    outputfile.write("\n")   
    outputfile.write("\n")  
    outputfile.write("\n")      



def sys_top(blocks, lines, end_of_block,outputfile):
    print("SYS TOP / SYS TOP ALL")

    elements = 0
    head = ["Name"]   
    Iteration = 1
    current_block = []
    for i in range(end_of_block-blocks):    
        tokens = lines[blocks+i].split()
        try: 
            if len(tokens)>0:
                #print(tokens)
                elements = elements + 1 
                if tokens[0] == "Run" or tokens[1] == "Time:":
                    current_block.append(i)
                    head.append(str(Iteration))
                    Iteration = Iteration + 1   
                    elements = 0 
        except:
            print("jump! sys top")
    processes = []
    
    elements = elements - 1
    print("elements " +str(elements))
    print("Iterations:" + str(Iteration))
    print(head)
    print(len(current_block))

    for i in range(len(current_block)):

        for j in range(elements):
            #Blockstart + n-th Block Offset + RunTime Lines Offset(2)
            tokens = lines[blocks + current_block[i] + j + 2].split()
            token_tuple = (tokens[0],tokens[1])
            processes.append(token_tuple)  


    all_detected_processes = []
    [all_detected_processes.append(x) for x in processes if x not in all_detected_processes]  
    

    data = []
    for i in range(len(all_detected_processes)):    
        data.append(["-"])


    for i in range(len(all_detected_processes)):     
        for j in range(len(current_block)):
            data[i].append("-")
    
    
    for k in range(len(all_detected_processes)):
        data[k][0] = all_detected_processes[k]



    for i in range(len(current_block)):

        for j in range(elements):
            #Blockstart + n-th Block Offset + RunTime Lines Offset(2)
            tokens = lines[blocks + current_block[i] + j + 2].split()
            curr_process_tuple = (tokens[0], tokens[1]) 
            
            #search the process in the Table and save memdata in the table
            for k in range(len(all_detected_processes)):
                if curr_process_tuple == data[k][0]:
                    #there is an column line after the memory column. The last column is an int not a float -> check if there is a "."
                    if "." in tokens[-1]: 
                        data[k][1+i] = tokens[-1] 
                    else:
                        data[k][1+i] = tokens[-2]             
            
    
#Problem: Reihenfolge stimmt nicht zwischen den Tabellen. Tabellen könnten unterschiedliche elemente haben. Wir könnten mehr elemente hier haben.



    outputfile.write("### SYS TOP MEMORY / SYS TOP ALL MEMORY")
    outputfile.write("\n")    
    outputfile.write(tabulate(data,headers=head,tablefmt="grid"))
    outputfile.write("\n")   
    outputfile.write("\n")  
    outputfile.write("\n")      
    
    return data





def general_system_information(gen_start_line, lines, end_of_block,outputfile):
    print("GENERAL DEVICE INFORMATION")
    
    head = ["Name", "value"]
    data = []


    table_iter = 0
    for i in range(end_of_block-gen_start_line[0]-1):    
        tokens = lines[gen_start_line[0]+i].split()  
        try:
            if len(tokens)>0:
                      
                if tokens[0] == "Version:":
                    data.append([str(tokens[0])])
                    data[table_iter].append(str(tokens[1])+ " " + str(tokens[2]))
                    table_iter = table_iter + 1
                    #get Version number for return value
                    Version_number_array = tokens[2].split(".")
                    Version_number_array[0] = Version_number_array[0][1]
                    Version_number_array[2] = Version_number_array[0][0]                    


                if tokens[0] == "Hostname:":
                    data.append([str(tokens[0])])
                    data[table_iter].append(str(tokens[1]))
                    table_iter = table_iter + 1

                if tokens[0] == "Serial-Number:":
                    data.append([str(tokens[0])])
                    data[table_iter].append(str(tokens[1]))
                    table_iter = table_iter + 1
                    
                if tokens[0] == "Current" and tokens[1] == "HA":
                    data.append([str(tokens[0])+ " "+ str(tokens[1]) + " "+ str(tokens[2])])
                    data[table_iter].append(str(tokens[3]))
                    table_iter = table_iter + 1                    

                if tokens[0] == "System" and tokens[1] == "time:":
                    data.append([str(tokens[0])+ " "+ str(tokens[1])])
                    data[table_iter].append(str(tokens[3]) + " " + str(tokens[4]) + " " + str(tokens[5]) + " " + str(tokens[6]) )
                    table_iter = table_iter + 1


        except:
            print("jump! general sys information")
             
    
    
    outputfile.write("### GENERAL DEVICE INFORMATION")
    outputfile.write("\n")    
    outputfile.write(tabulate(data,headers=head,tablefmt="grid"))
    outputfile.write("\n")   
    outputfile.write("\n")  
    outputfile.write("\n")          
    return Version_number_array

def conserve(block, lines, end_of_block, outputfile, data_mem_overview):
    print("CONSERVE MODE ENTERED")
    
    threshold_missclac_timestamp = []
    MB = 1000
    head = ["Name","current"]   
    current_block = []
    red_array = []
    used_array = []
    elements = 0        #elements in block
    elements_stop_counter = 0
    start = 0           #block is starting
    red = 0             #conserve mode consistency red threshold
    used = 1           #conserve mode consistency used total memory
    for i in range(end_of_block-block):    
        tokens = lines[block+i].split()

        try: 
            if len(tokens)>0:

                for j in range(len(tokens)-1):
                    if (tokens[j] == "mode" and tokens[j+1] == "entered\"") or (tokens[j] == "enters" and tokens[j+1] == "memory"):               
                        start_block = 1 

                if tokens[3] == "MemTotal:" and start_block == 1:
                    start = 1
                    red = 0
                    used = 1
                    current_block.append(i-1)
                    head.append(tokens[1] +" "+tokens[2])
            
                if tokens[3] == "VmallocChunk:" and start_block == 1:
                    start = 0
                    elements_stop_counter = 1
                    start_block = 0 
                    
                if start == 1 and elements_stop_counter == 0:
                    elements = elements + 1
                
                for j in range(len(tokens)-1):
                    
                    if tokens[j].split("=\"")[0] ==  "used":   
                        used = int(tokens[j].split("=\"")[1])
                        used_array.append(used)

                        
                    if tokens[j].split("=\"")[0] ==  "red":                     
                        red = int(tokens[j].split("=\"")[1]) 
                        red_array.append(red)
                        threshold_missclac_timestamp.append(tokens[1] + " " + tokens[2])
                    
                    #pop last element so we only track conserve mode entered
                    if tokens[j] ==  "exits":                     
                        used_array.pop(-1)
                        red_array.pop(-1)
                
                                                                                      

                   


        except:
            print("jump! conserve")



    for i in range(len(used_array)):
        if used_array[i] < red_array[i]:
            outputfile.write("BUG detected: conserve mode threshold was calculated wrong at " + str(threshold_missclac_timestamp[i]))
            outputfile.write("\n")                          
            outputfile.write("used: " + str(used_array[i]) + " vs red: " +str(red_array[i]))   
            outputfile.write("\n")  
            outputfile.write("\n")   
    
    
    data = []
    for i in range(elements):    
        data.append(["-"])
         
    
    print(len(current_block)+1) 
    for i in range(len(current_block)+1):  
        for i in range(elements):             
            data[i].append("-")
        

  
    #current usage of the device from ### get hardware memory
    try:
        for i in range(len(data_mem_overview)):
            data[i][1] = str(int(data_mem_overview[i][1])/MB) + " MB" 
    except:
        print("### get hardware memory not found")    
        
    #copy names into table
    for i in range(elements):
        tokens = lines[block + current_block[0]+i+1].split()       
        data[i][0] = tokens[3]   

    #copy elements into table    
    for j in range(len(current_block)):
        for i in range(elements):
            tokens = lines[block + current_block[j]+i+1].split() 
            
            # diagnose hardware sysinfo memory exists
            try:
                comparison = (int(tokens[4]) - int(data_mem_overview[i][1]))/MB               
                if comparison >= int(0):
                    data[i][j+2]  = str(int(tokens[4])/MB) +" MB"  + " (+"+ str(comparison) +" MB)"

                if comparison < 0:
                    data[i][j+2]  = str(int(tokens[4])/MB) +" MB"  + " ("+ str(comparison) +" MB)"
            
            # diagnose hardware sysinfo memory does not exists
            except:
                data[i][j+2] = tokens[4]
                      

    print("DATA")
    print(elements)

    outputfile.write("### diagnose debug crashlog read")
    outputfile.write("\n")    
    outputfile.write(tabulate(data,headers=head,tablefmt="grid"))
    outputfile.write("\n")
    outputfile.write("\n")  
    outputfile.write("\n")  
    


################################################################################################################################
######################################################  CPU #######################################################################
################################################################################################################################

def sys_top_cpu(blocks, lines, end_of_block,outputfile):
    print("SYS TOP CPU / SYS TOP ALL CPU")

    elements = 0
    head = ["Name"]   
    Iteration = 1
    current_block = []
    for i in range(end_of_block-blocks):    
        tokens = lines[blocks+i].split()
        try: 
            if len(tokens)>0:
                elements = elements + 1 
                if tokens[0] == "Run" or tokens[1] == "Time:":
                    current_block.append(i)
                    head.append(str(Iteration))
                    Iteration = Iteration + 1   
                    elements = 0 
        except:
            print("jump! sys top CPU")
    processes = []
    
    elements = elements - 1

    for i in range(len(current_block)):

        for j in range(elements):
            #Blockstart + n-th Block Offset + RunTime Lines Offset(2)
            tokens = lines[blocks + current_block[i] + j + 2].split()
            token_tuple = (tokens[0],tokens[1])
            processes.append(token_tuple)  


    all_detected_processes = []
    [all_detected_processes.append(x) for x in processes if x not in all_detected_processes]  
    

    data = []
    for i in range(len(all_detected_processes)):    
        data.append(["-"])


    for i in range(len(all_detected_processes)):     
        for j in range(len(current_block)):
            data[i].append("-")
    
    
    for k in range(len(all_detected_processes)):
        data[k][0] = all_detected_processes[k]



    for i in range(len(current_block)):

        for j in range(elements):
            #Blockstart + n-th Block Offset + RunTime Lines Offset(2)
            tokens = lines[blocks + current_block[i] + j + 2].split()
            curr_process_tuple = (tokens[0], tokens[1]) 
            
            #search the process in the Table and save memdata in the table
            for k in range(len(all_detected_processes)):
                if curr_process_tuple == data[k][0]:
                    #there is an column line after the memory column. The last column is an int not a float -> check if there is a "."
                    if "." in tokens[-1]: 
                        data[k][1+i] = tokens[-2] 
                    else:
                        data[k][1+i] = tokens[-3]             
            
    
#Problem: Reihenfolge stimmt nicht zwischen den Tabellen. Tabellen könnten unterschiedliche elemente haben. Wir könnten mehr elemente hier haben.



    outputfile.write("### SYS TOP CPU / SYS TOP ALL CPU")
    outputfile.write("\n")    
    outputfile.write(tabulate(data,headers=head,tablefmt="grid"))
    outputfile.write("\n")   
    outputfile.write("\n")  
    outputfile.write("\n")  

    return data

    

def diag_session_list(blocks, lines, end_of_block,outputfile):
    print("diag sys session list")



    #https://community.fortinet.com/t5/FortiGate/Troubleshooting-Tip-FortiGate-session-table-information/ta-p/196988
    data = []
    head = ["dirty", "may_dirty","local","oe","re","ndr", "npu", "rem", "eph","br","redir","wccp","nlb","os","rs","auth","block","ext","log" , "app_valid"]       
    for i in range(17):    
        data.append([int(0)])


    for i in range(17):     
        for j in range(len(head)):
            data[i].append(int(0))


    for i in range(17):
        data[i][0] = i+1
        
    no_ofld_reason = 0
    total_sessions = 0
    dirty_gwy = []
    for i in range(end_of_block-blocks):    
        tokens = lines[blocks+i].split()
        try: 
            if len(tokens)>0:
                
                if tokens[0] == "no_ofld_reason:" and len(tokens) == 1:
                    no_ofld_reason = no_ofld_reason + 1
                
                if tokens[0] == "session" and tokens[1] == "info:":
                    proto = tokens[2].split("=")[1] 
                    int_proto = int(proto) -1
                    dirty = 0
                    total_sessions = total_sessions + 1
                    
                    
                if tokens[0].split("=")[0] == "state":

                    first_state = tokens[0].split("=")[1]
                    
                    if first_state == "dirty":                          #done by the cpu
                        data[int_proto][1] = data[int_proto][1] + 1
                        dirty = 1
                                                    
                    if first_state == "may_dirty":
                        data[int_proto][2] = data[int_proto][2] + 1                            
                    
                    if first_state == "local":                     
                        data[int_proto][3] = data[int_proto][3] + 1                    
                    
                    if first_state == "oe":
                        data[int_proto][4] = data[int_proto][4] + 1

                    if first_state == "re":
                        data[int_proto][5] = data[int_proto][5] + 1

                    if first_state == "ndr":                            # only nturbo
                        data[int_proto][6] = data[int_proto][6] + 1                               
                            
                    if first_state == "npu":
                        data[int_proto][7] = data[int_proto][7] + 1        

                    if first_state == "rem":
                        data[int_proto][8] = data[int_proto][8] + 1
                    
                    if first_state == "eph":
                        data[int_proto][9] = data[int_proto][9] + 1                    
                    
                    if first_state == "br":
                        data[int_proto][10] = data[int_proto][10] + 1        

                    if first_state == "redir":                          # not offloaded
                        data[int_proto][11] = data[int_proto][11] + 1        
                    
                    if first_state == "wccp":
                        data[int_proto][12] = data[int_proto][12] + 1                            
                    
                    if first_state == "nlb":
                        data[int_proto][13] = data[int_proto][13] + 1                            
                    
                    if first_state == "os":
                        data[int_proto][14] = data[int_proto][14] + 1                            
                    
                    if first_state == "rs":
                        data[int_proto][15] = data[int_proto][15] + 1   
                            
                    if first_state == "auth":                           # not offloaded
                        data[int_proto][16] = data[int_proto][16] + 1                               
                            
                    if first_state == "block":
                        data[int_proto][17] = data[int_proto][17] + 1                               
                            
                    if first_state == "ext":
                        data[int_proto][18] = data[int_proto][18] + 1   
                            
                    if first_state == "log":
                        data[int_proto][19] = data[int_proto][19] + 1                                                                                                                                       
                            
                    if first_state == "app_valid":
                        data[int_proto][20] = data[int_proto][20] + 1                            
                    
                    
                    
                    for j in range(len(tokens)):
                  
                        if tokens[j] == "dirty":
                            data[int_proto][1] = data[int_proto][1] + 1
                            dirty = 1
                            
                        if tokens[j] == "may_dirty":
                            data[int_proto][2] = data[int_proto][2] + 1                            
                    
                        if tokens[j] == "local":
                            data[int_proto][3] = data[int_proto][3] + 1                    
                    
                        if tokens[j] == "oe":
                            data[int_proto][4] = data[int_proto][4] + 1

                        if tokens[j] == "re":
                            data[int_proto][5] = data[int_proto][5] + 1

                        if tokens[j] == "ndr":
                            data[int_proto][6] = data[int_proto][6] + 1                               
                            
                        if tokens[j] == "npu":
                            data[int_proto][7] = data[int_proto][7] + 1        

                        if tokens[j] == "rem":
                            data[int_proto][8] = data[int_proto][8] + 1
                    
                        if tokens[j] == "eph":
                            data[int_proto][9] = data[int_proto][9] + 1                    
                    
                        if tokens[j] == "br":
                            data[int_proto][10] = data[int_proto][10] + 1        

                        if tokens[j] == "redir":
                            data[int_proto][11] = data[int_proto][11] + 1        
                    
                        if tokens[j] == "wccp":
                            data[int_proto][12] = data[int_proto][12] + 1                            
                    
                        if tokens[j] == "nlb":
                            data[int_proto][13] = data[int_proto][13] + 1                            
                    
                        if tokens[j] == "os":
                            data[int_proto][14] = data[int_proto][14] + 1                            
                    
                        if tokens[j] == "rs":
                            data[int_proto][15] = data[int_proto][15] + 1   
                            
                        if tokens[j] == "auth":
                            data[int_proto][16] = data[int_proto][16] + 1                               
                            
                        if tokens[j] == "block":
                            data[int_proto][17] = data[int_proto][17] + 1                               
                            
                        if tokens[j] == "ext":
                            data[int_proto][18] = data[int_proto][18] + 1   
                            
                        if tokens[j] == "log":
                            data[int_proto][19] = data[int_proto][19] + 1                                                                                                                                       
                            
                        if tokens[j] == "app_valid":
                            data[int_proto][20] = data[int_proto][20] + 1                                                                                    
                                                        
                

                if dirty == 1 and tokens[0] == "orgin->sink:":
                        dirty_gwy.append(lines[blocks+i])
                        dirty_gwy_count = Counter(dirty_gwy)

                        
        except:
            print("jump! diag sys session list")
   
    
    
    #sort sessions gwy
    try:
        tuples = []
        for i in range(len(dirty_gwy_count)):
            key, value = dirty_gwy_count.popitem()  
            print(value)
            tuple = (key, value)
            tuples.append(tuple) 
                  
        tuples_sorted = sorted(tuples, key=lambda x: int(x[1]))
        tuples_sorted.reverse()
    except Exception as e:
        outputfile.write("\n")   
        outputfile.write("sort sessions gwy failed because:") 
        outputfile.write("\n") 
        outputfile.write(str(e)) 
        outputfile.write("\n") 
    
    outputfile.write("\n")
    outputfile.write("session list table")
    outputfile.write("\n")
    outputfile.write("### diag sys session list")        
    outputfile.write("\n")    
    outputfile.write(tabulate(data,headers=head,tablefmt="grid"))
    outputfile.write("\n") 
    outputfile.write("Sessions which are not offloaded: " + str(no_ofld_reason))
    outputfile.write("\n")
    outputfile.write("\n")
    outputfile.write("TOTAL SESSIONS: "+ str(total_sessions))
    outputfile.write("\n")
    outputfile.write("Dirty Sessions by gwy:")
    outputfile.write("\n")
    for i in range(len(tuples_sorted)):
        outputfile.write("\n")
        
        outputfile.write(tuples_sorted[i][0] + " COUNT = " + str(tuples_sorted[i][1]))
        outputfile.write("\n") 
    outputfile.write("\n")
    outputfile.write("\n")  








def sys_performance_status(sys_start_line, lines, end_of_block,outputfile):
    print("get system performance status")
    outputfile.write("\n") 
    outputfile.write("\n") 
    outputfile.write("### get sys performance status")
    outputfile.write("\n") 
    outputfile.write("\n") 
    
    #irq, softirqs
    data = [0,0]
    
    for i in range(end_of_block-sys_start_line[0]-1):    
        tokens = lines[sys_start_line[0]+i].split() 
        
        try:
            if len(tokens)>0:
                for j in range(len(tokens)):
                    if "states" in tokens[j]: 
                        outputfile.write(lines[sys_start_line[0]+i]) 
                        outputfile.write("\n") 

                    if "irq" == tokens[j]:                                                                        
                        irq = int(tokens[j-1][:-1])
                        if irq > int(data[0]):
                            data[0] = irq
 
                    if "softirq" == tokens[j]: 
                        softirq = int(tokens[j-1][:-1])
                        if int(softirq) > int(data[1]):  
                            data[1] = softirq
                                          
          
    
                    if "sessions:" == tokens[j] or "session" == tokens[j]:                         
                            outputfile.write(lines[sys_start_line[0]+i]) 
                            outputfile.write("\n")
    
                    if "NPU" == tokens[j]: 
                            outputfile.write(lines[sys_start_line[0]+i]) 
                            outputfile.write("\n")
                                                  
                    if "nTurbo" == tokens[j]:   
                            outputfile.write(lines[sys_start_line[0]+i]) 
                            outputfile.write("\n")
                                                
        except:
            print("jump! get system performance status")


    return data

####################################################################################################
#################################### MAIN ##########################################################
####################################################################################################
        
def find_blocks(filename):


    global flag_a 
    flag_a = True 

    file = open(filename,"r", encoding='cp850') 
    lines = file.readlines()    
    file.close()


    general_system_lines = []
    sys_top_lines = []
    cmdb_occurances = []
    tmp_occurances = []
    shm_occurances = []    
    mem_overv = []
    slabinfo = []
    crashlogs = []
    ips_session = []
    mig = []
    wad_table = []
    sys_settings = []
    session_list = []
    performance_status = []
    proxy_stats = []
    wad_table_all =[]
    cmd_used_at = []


    #delete empty cmd lines
    i = 0
    for line in lines:
        tokens = line.split()
        if len(tokens) == 2 and tokens[1] == "#":
            del lines[i]
  
        i = i + 1        


    
    i = 0
    for line in lines:
        
        tokens = line.split()

        len_tokens = len(tokens)
        for j in range(len(tokens)):
            
            
            
            if tokens[j] == "diag" or tokens[j] == "diagnose" or tokens[j] == "get" or tokens[j] == "fnsysctl" or tokens[j] == "exec" or tokens[j] == "show" or tokens[j] == "de" or tokens[j] == "di":
                if tokens[j-1] == "#" or tokens[j-1] == "###":   #workaround for wad memory all - some cmem objects are called diag
                    cmd_used_at.append(i)

                
        
        if len(tokens) > 3:
            for t in range(len_tokens-1):
                if tokens[t] == "system" and tokens[t+1] == "status":
                    general_system_lines.append(i)            
            
                if tokens[t] == "-l" and tokens[t+1] == "/dev/cmdb":
                    cmdb_occurances.append(i)
 
                if tokens[t] == "-l" and tokens[t+1] == "/tmp":
                    tmp_occurances.append(i)
                    
                if tokens[t] == "-l" and tokens[t+1] == "/dev/shm":
                    shm_occurances.append(i)
                    
                if tokens[t] == "hardware" and tokens[t+1] == "memory":
                    mem_overv.append(i)   
                    
                if tokens[t] == "sysinfo" and tokens[t+1] == "slab":
                    slabinfo.append(i)                                        

                if tokens[t] == "crashlog" and tokens[t+1] == "read":
                    crashlogs.append(i)     
                    
                if tokens[t] == "ips" and tokens[t+1] == "session":
                    ips_session.append(i)                                                  

                    

        if len(tokens) > 4:
            for t in range(len_tokens-2):
                if tokens[t] == "system" and tokens[t+1] == "performance" and tokens[t+2] == "status":
                    performance_status.append(i)    

                if tokens[t] == "sys" and tokens[t+1] == "session" and tokens[t+2] == "list":
                    session_list.append(i)    
        
                if tokens[t] == "sys" and tokens[t+1] == "top":
                    sys_top_lines.append(i)                       
        
                if tokens[t] == "sys" and tokens[t+1] == "top-all":
                    sys_top_lines.append(i)                       
                        
                if tokens[t] == "application" and tokens[t+1] == "miglogd" and tokens[t+2] == "6":
                    mig.append(i)                     

                if tokens[t] == "wad" and tokens[t+1] == "memory" and tokens[t+2] == "sum":
                    wad_table.append(i)

                if tokens[t] == "wad" and tokens[t+1] == "memory" and tokens[t+2] == "all":
                    wad_table_all.append(i)
                    
                if tokens[t] == "application" and tokens[t+1] == "wad" and tokens[t+2] == "803":
                    wad_table.append(i)
                           
                if tokens[t] == "full-configuration" and tokens[t+1] == "system" and tokens[t+2] == "settings":
                    sys_settings.append(i)                        
            
                if tokens[t] == "proxy" and tokens[t+1] == "stats" and tokens[t+2] == "all":
                    proxy_stats.append(i)   

        i = i+1
        
        

    output_file_split = filename[:len(filename)-4]
    output_file_name = "output_" + output_file_split + ".txt" 
    outputfile = open(output_file_name,"w") 

    outputfile.write("\n")
    outputfile.write("\n") 
    outputfile.write("\n")
    outputfile.write("###################################################################################################################################")
    outputfile.write("\n")    
    outputfile.write("###################################################################################################################################")
    outputfile.write("\n")    
    outputfile.write("##############################################         MEMORY            ###########################################################")        
    outputfile.write("\n")    
    outputfile.write("###################################################################################################################################")
    outputfile.write("\n")        
    outputfile.write("###################################################################################################################################")
    outputfile.write("\n")    
    outputfile.write("\n")         
    outputfile.write("\n") 

    
    #get system status
    try: 
        if len(general_system_lines)>0:
            end_of_block = cmd_used_at.index(general_system_lines[0])
            if end_of_block == len(cmd_used_at)-1:        
                Version_number_array = general_system_information(general_system_lines,lines,i,outputfile)       
            else:
                Version_number_array = general_system_information(general_system_lines,lines,cmd_used_at[end_of_block+1], outputfile)      
    
        if len(general_system_lines) == 0: 
            outputfile.write("\n")   
            outputfile.write("get system status not found") 
            outputfile.write("\n")   
    except Exception as e:
        outputfile.write("\n")   
        outputfile.write("#get system status failed because:") 
        outputfile.write("\n") 
        outputfile.write(str(e)) 
        outputfile.write("\n") 
        outputfile.write(traceback.format_exc())         
        outputfile.write("\n") 
        outputfile.write("\n") 
        outputfile.write("contact author with the log file") 
        outputfile.write("\n") 
        outputfile.write("\n")         

    #config system settings
    try: 
        if len(sys_settings)>0:       
            end_of_block = cmd_used_at.index(sys_settings[0])
            if end_of_block == len(cmd_used_at)-1:        
                settings = sys_set(sys_settings,lines,i)       
            else:
                settings = sys_set(sys_settings,lines,cmd_used_at[end_of_block+1])  
    
        if len(sys_settings) == 0: 
            outputfile.write("\n")   
            outputfile.write("config system settings not found") 
            outputfile.write("\n") 
    except Exception as e:
        outputfile.write("\n")   
        outputfile.write("#config system settings failed because:") 
        outputfile.write("\n") 
        outputfile.write(str(e)) 
        outputfile.write("\n") 
        outputfile.write(traceback.format_exc())         
        outputfile.write("\n") 
        outputfile.write("\n") 
        outputfile.write("contact author with the log file") 
        outputfile.write("\n") 
        outputfile.write("\n")   
        
        
                   
    #diagnose hardware sysinfo memory
    data_mem_overview = []
    try:
        if len(mem_overv)>0:
            end_of_block = cmd_used_at.index(mem_overv[0])
            if end_of_block == len(cmd_used_at)-1:        
                data_mem_overview = mem_overview(mem_overv,lines,i,outputfile)       
            else:
                data_mem_overview = mem_overview(mem_overv,lines,cmd_used_at[end_of_block+1], outputfile)                                
    
        if len(mem_overv) == 0: 
            outputfile.write("\n")   
            outputfile.write("diagnose hardware sysinfo memory not found") 
            outputfile.write("\n")   
        
    except Exception as e:
        outputfile.write("\n")   
        outputfile.write("#diagnose hardware sysinfo memory failed because:") 
        outputfile.write("\n") 
        outputfile.write(str(e)) 
        outputfile.write("\n") 
        outputfile.write(traceback.format_exc())         
        outputfile.write("\n") 
        outputfile.write("\n") 
        outputfile.write("contact author with the log file") 
        outputfile.write("\n") 
        outputfile.write("\n")  

    #diagnose debug crashlog read    
    try:
        if len(crashlogs)>0:
            end_of_block = cmd_used_at.index(crashlogs[0])        
            if end_of_block == len(cmd_used_at)-1:
                conserve(crashlogs[0],lines,i, outputfile, data_mem_overview)
            else:
                conserve(crashlogs[0],lines,cmd_used_at[end_of_block+1], outputfile, data_mem_overview)            
    
        if len(crashlogs) == 0: 
            outputfile.write("\n")   
            outputfile.write("diagnose debug crashlog read not found") 
            outputfile.write("\n")   

    except Exception as e:
        outputfile.write("\n")   
        outputfile.write("#diagnose debug crashlog read  failed because:") 
        outputfile.write("\n") 
        outputfile.write(str(e)) 
        outputfile.write("\n") 
        outputfile.write(traceback.format_exc())         
        outputfile.write("\n") 
        outputfile.write("\n") 
        outputfile.write("contact author with the log file") 
        outputfile.write("\n") 
        outputfile.write("\n")  
        
        
    #diag sys top MEMORY
    try:
        if len(sys_top_lines)>0:
            for j in range(len(sys_top_lines)):                     
                end_of_block = cmd_used_at.index(sys_top_lines[j])
                if end_of_block == len(cmd_used_at)-1:            
                    data_sys_top = sys_top(sys_top_lines[j],lines,i,outputfile)
                else:
                    data_sys_top = sys_top(sys_top_lines[j],lines,cmd_used_at[end_of_block+1], outputfile)      
    
        if len(sys_top_lines) == 0: 
            outputfile.write("\n")   
            outputfile.write("diag sys top not found") 
            outputfile.write("\n") 

    except Exception as e:
        outputfile.write("\n")   
        outputfile.write("#diag sys top MEMORY failed because:") 
        outputfile.write("\n") 
        outputfile.write(str(e)) 
        outputfile.write("\n") 
        outputfile.write(traceback.format_exc())         
        outputfile.write("\n") 
        outputfile.write("\n") 
        outputfile.write("contact author with the log file") 
        outputfile.write("\n") 
        outputfile.write("\n")  

    # /DEV/CMDB
    try: 
        if len(cmdb_occurances)>0:
            end_of_block = cmd_used_at.index(cmdb_occurances[0])
            if end_of_block == len(cmd_used_at)-1:        
                cmdb(cmdb_occurances,lines,i,outputfile)
            else:
                cmdb(cmdb_occurances,lines,cmd_used_at[end_of_block+1], outputfile)        
    
        if len(cmdb_occurances) == 0: 
            outputfile.write("\n")   
            outputfile.write("/DEV/CMDB not found") 
            outputfile.write("\n")     

    except Exception as e:
        outputfile.write("\n")   
        outputfile.write("# /DEV/CMDB failed because:") 
        outputfile.write("\n") 
        outputfile.write(str(e)) 
        outputfile.write("\n") 
        outputfile.write(traceback.format_exc())         
        outputfile.write("\n") 
        outputfile.write("\n") 
        outputfile.write("contact author with the log file") 
        outputfile.write("\n") 
        outputfile.write("\n")  
        
    # /TMP         
    try:
        if len(tmp_occurances)>0:
            end_of_block = cmd_used_at.index(tmp_occurances[0])
            if end_of_block == len(cmd_used_at)-1:        
                tmp(tmp_occurances,lines,i,outputfile)
            else:
                tmp(tmp_occurances,lines,cmd_used_at[end_of_block+1], outputfile)        
    
        if len(tmp_occurances) == 0: 
            outputfile.write("\n")   
            outputfile.write("/TMP not found") 
            outputfile.write("\n")     

    except Exception as e:
        outputfile.write("\n")   
        outputfile.write("# /TMP failed because:") 
        outputfile.write("\n") 
        outputfile.write(str(e)) 
        outputfile.write("\n") 
        outputfile.write(traceback.format_exc())         
        outputfile.write("\n") 
        outputfile.write("\n") 
        outputfile.write("contact author with the log file") 
        outputfile.write("\n") 
        outputfile.write("\n")  

    # /DEV/SHM        
    try: 
        if len(shm_occurances)>0:
            end_of_block = cmd_used_at.index(shm_occurances[0])
            if end_of_block == len(cmd_used_at)-1:        
                shm(shm_occurances,lines,i,outputfile)
            else:
                shm(shm_occurances,lines,cmd_used_at[end_of_block+1], outputfile)        
         
        if len(shm_occurances) == 0: 
            outputfile.write("\n")   
            outputfile.write("/DEV/SHM not found") 
            outputfile.write("\n")     
 
    except Exception as e:
        outputfile.write("\n")   
        outputfile.write("# /DEV/SHM  failed because:") 
        outputfile.write("\n") 
        outputfile.write(str(e)) 
        outputfile.write("\n") 
        outputfile.write(traceback.format_exc())         
        outputfile.write("\n") 
        outputfile.write("\n") 
        outputfile.write("contact author with the log file") 
        outputfile.write("\n") 
        outputfile.write("\n")      
     
    #diagnose hardware sysinfo slab   
    try:
        if len(slabinfo)>0:
            end_of_block = cmd_used_at.index(slabinfo[0])
            if end_of_block == len(cmd_used_at)-1:        
                slab(slabinfo,lines,i,outputfile)
            else:
                slab(slabinfo,lines,cmd_used_at[end_of_block+1], outputfile)        
        
        if len(slabinfo) == 0: 
            outputfile.write("\n")   
            outputfile.write("diagnose hardware sysinfo slab not found") 
            outputfile.write("\n")

    except Exception as e:
        outputfile.write("\n")   
        outputfile.write("#diagnose hardware sysinfo slab failed because:") 
        outputfile.write("\n") 
        outputfile.write(str(e)) 
        outputfile.write("\n") 
        outputfile.write(traceback.format_exc())         
        outputfile.write("\n") 
        outputfile.write("\n") 
        outputfile.write("contact author with the log file") 
        outputfile.write("\n") 
        outputfile.write("\n")  
        
    #get ips session
    try:
        if len(ips_session)>0:
            end_of_block = cmd_used_at.index(ips_session[0])
            if end_of_block == len(cmd_used_at)-1:        
                ips_s(ips_session,lines,i,outputfile)
            else:
                ips_s(ips_session,lines,cmd_used_at[end_of_block+1], outputfile)        
        
        if len(ips_session) == 0:
            outputfile.write("\n")
            outputfile.write("get ips session not found")   
            outputfile.write("\n")

    except Exception as e:
        outputfile.write("\n")   
        outputfile.write("#get ips session failed because:") 
        outputfile.write("\n") 
        outputfile.write(str(e)) 
        outputfile.write("\n") 
        outputfile.write(traceback.format_exc())         
        outputfile.write("\n") 
        outputfile.write("\n") 
        outputfile.write("contact author with the log file") 
        outputfile.write("\n") 
        outputfile.write("\n")  
          
    #diagnose test application miglogd 6
    try:
        if len(mig)>0:
            end_of_block = cmd_used_at.index(mig[0])
            if end_of_block == len(cmd_used_at)-1:        
                miglogd(mig,lines,i,outputfile)
            else:
                miglogd(mig,lines,cmd_used_at[end_of_block+1], outputfile)        
    
        if len(mig) == 0:
            outputfile.write("\n")
            outputfile.write("diagnose test application miglogd 6 not found") 
            outputfile.write("\n")

    except Exception as e:
        outputfile.write("\n")   
        outputfile.write("#diagnose test application miglogd 6 failed because:") 
        outputfile.write("\n") 
        outputfile.write(str(e)) 
        outputfile.write("\n") 
        outputfile.write(traceback.format_exc())         
        outputfile.write("\n") 
        outputfile.write("\n") 
        outputfile.write("contact author with the log file") 
        outputfile.write("\n") 
        outputfile.write("\n")  
        
    #diagnose wad memory sum
    try:
        if len(wad_table)>0:
            end_of_block = cmd_used_at.index(wad_table[0])
            if end_of_block == len(cmd_used_at)-1:        
                wad_data_table = wad_t(wad_table,lines,i,outputfile)
            else:
                wad_data_table = wad_t(wad_table[0],lines,cmd_used_at[end_of_block+1], outputfile)        
    
        if len(wad_table) == 0:
            outputfile.write("\n")
            outputfile.write("diagnose wad memory sum not found or empty")         
            outputfile.write("\n")

    except Exception as e:
        outputfile.write("\n")   
        outputfile.write("#diagnose wad memory sum failed because:") 
        outputfile.write("\n") 
        outputfile.write(str(e)) 
        outputfile.write("\n") 
        outputfile.write(traceback.format_exc())         
        outputfile.write("\n") 
        outputfile.write("\n") 
        outputfile.write("contact author with the log file") 
        outputfile.write("\n") 
        outputfile.write("\n")              


    #diagnose wad memory all
    try:
        if len(wad_table_all)>0:
            end_of_block = cmd_used_at.index(wad_table_all[0])
            print("wad " + str(cmd_used_at.index(wad_table_all[0])))
            print(cmd_used_at)
            print(str(wad_table_all[0]))
            print(end_of_block)      
            if end_of_block == len(cmd_used_at)-1:        
                wad_data_table_all = wad_all(wad_table_all,lines,i,outputfile)
            else:
                wad_data_table_all = wad_all(wad_table_all[0],lines,cmd_used_at[end_of_block+1], outputfile)        
    
        if len(wad_table_all) == 0:
            outputfile.write("\n")
            outputfile.write("diagnose wad memory all not found or empty")         
            outputfile.write("\n")

    except Exception as e:
        outputfile.write("\n")   
        outputfile.write("#diagnose wad memory all failed because:") 
        outputfile.write("\n") 
        outputfile.write(str(e)) 
        outputfile.write("\n") 
        outputfile.write(traceback.format_exc())         
        outputfile.write("\n") 
        outputfile.write("\n") 
        outputfile.write("contact author with the log file") 
        outputfile.write("\n") 
        outputfile.write("\n")   





##########################
############## CPU ######
##########################

    outputfile.write("\n")
    outputfile.write("\n") 
    outputfile.write("\n")
    outputfile.write("###################################################################################################################################")
    outputfile.write("\n")
    outputfile.write("###################################################################################################################################")
    outputfile.write("\n")
    outputfile.write("##############################################         CPU              ###########################################################")        
    outputfile.write("\n")
    outputfile.write("###################################################################################################################################")    
    outputfile.write("\n")
    outputfile.write("###################################################################################################################################")
    outputfile.write("\n")    
    outputfile.write("\n")         
    outputfile.write("\n") 
    
    #get system performance status
    #perf_data = [%irq, %softirqs]
    try:
        if len(performance_status)>0:
            end_of_block = cmd_used_at.index(performance_status[0])
            if end_of_block == len(cmd_used_at)-1:        
                perf_data = sys_performance_status(performance_status,lines,i,outputfile)       
            else:
                perf_data = sys_performance_status(performance_status,lines,cmd_used_at[end_of_block+1], outputfile)      
                
            #print(perf_data)
        if len(performance_status) == 0: 
            outputfile.write("\n")   
            outputfile.write("get system performance status not found") 
            outputfile.write("\n")       
    
    except Exception as e:
        outputfile.write("\n")   
        outputfile.write("#get system performance status failed because:") 
        outputfile.write("\n") 
        outputfile.write(str(e)) 
        outputfile.write("\n") 
        outputfile.write(traceback.format_exc())         
        outputfile.write("\n") 
        outputfile.write("\n") 
        outputfile.write("contact author with the log file") 
        outputfile.write("\n") 
        outputfile.write("\n")  
    
    #diag sys top
    try:
        if len(sys_top_lines)>0:
            for j in range(len(sys_top_lines)):                     
                end_of_block = cmd_used_at.index(sys_top_lines[j])
                if end_of_block == len(cmd_used_at)-1:            
                    data_sys_top_cpu = sys_top_cpu(sys_top_lines[j],lines,i,outputfile)
                else:
                    data_sys_top_cpu = sys_top_cpu(sys_top_lines[j],lines,cmd_used_at[end_of_block+1], outputfile)        
    
        if len(sys_top_lines) == 0: 
            outputfile.write("\n")   
            outputfile.write("diag sys top not found") 
            outputfile.write("\n") 

    except Exception as e:
        outputfile.write("\n")   
        outputfile.write("#diag sys top failed because:") 
        outputfile.write("\n") 
        outputfile.write(str(e)) 
        outputfile.write("\n")
        outputfile.write(traceback.format_exc())         
        outputfile.write("\n") 
        outputfile.write("contact author with the log file") 
        outputfile.write("\n") 
        outputfile.write("\n")  

    #diag sys session list
    try:
        if len(session_list)>0:
            end_of_block = cmd_used_at.index(session_list[0])
            if end_of_block == len(cmd_used_at)-1:        
                diag_session_list(session_list[0],lines,i,outputfile)       
            else:
                diag_session_list(session_list[0],lines,cmd_used_at[end_of_block+1], outputfile)      
    
        if len(session_list) == 0: 
            outputfile.write("\n")   
            outputfile.write("diag sys session list not found") 
            outputfile.write("\n")   

    except Exception as e:
        outputfile.write("\n")   
        outputfile.write("#diag sys session list failed because:") 
        outputfile.write("\n") 
        outputfile.write(str(e)) 
        outputfile.write("\n") 
        outputfile.write(traceback.format_exc())         
        outputfile.write("\n") 
        outputfile.write("\n") 
        outputfile.write("contact author with the log file") 
        outputfile.write("\n") 
        outputfile.write("\n")  

    #diagnose sys proxy stats all
    try:
        if len(proxy_stats)>0:
            end_of_block = cmd_used_at.index(proxy_stats[0])
            if end_of_block == len(cmd_used_at)-1:        
                proxy_stats_table = proxy_stats_all(proxy_stats,lines,i,outputfile)
            else:
                proxy_stats_table = proxy_stats_all(proxy_stats[0],lines,cmd_used_at[end_of_block+1], outputfile)        
    
        if len(proxy_stats) == 0:
            outputfile.write("\n")
            outputfile.write("diagnose sys proxy stats all not found or empty")         
            outputfile.write("\n")
        
    except Exception as e:
        outputfile.write("\n")   
        outputfile.write("#diagnose sys proxy stats all because:") 
        outputfile.write("\n") 
        outputfile.write(str(e)) 
        outputfile.write("\n") 
        outputfile.write(traceback.format_exc())         
        outputfile.write("\n") 
        outputfile.write("\n") 
        outputfile.write("contact author with the log file") 
        outputfile.write("\n") 
        outputfile.write("\n")  
    
    outputfile.close()
   
   
   
#if __name__ == "__main__":
#    print(f"Arguments count: {len(sys.argv)}")
#    for i, arg in enumerate(sys.argv):
#        print(f"Argument {i:>6}: {arg}")#

#    find_blocks(sys.argv[1])

find_blocks("FG201FT921905883_debug.log")




