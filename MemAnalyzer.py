#Author
#desc
#docstrings
#github
#kommentare

#manual für installation und flags

#github test

################
#ROBUSTHEIT

#idee: für robustheit alle strings in lowercase vergleichen, falls die devs irgendwas ändern

#try catch debugmeldung

#Mögliche bug Ursache: Am anfang unsinn:
#['\x1b[H\x1b[JRun', 'Time:', '10', 'days,', '11', 'hours', 'and', '16', 'minutes']


#############################
#LESBARKEIT

#liste der Befehle die verwendet wurde für jeden Info Block + Zeile + größe des Blocks (auch wenn die nicht 100% übereinstimmt mit glogg)
#Im Zweifel kann man dann so überprüfen ob die Ausgabe legitim ist.




#################################
#TO DO FEATURES

#OUTPUT
#output sortieren -> active/cached, oder IPS/WAD, große Tabellen oben, kleine dinge unten

#debug log <-> try/catch error

#kein hardcode für Filereader

#mehrere Files einlesen

#flags. 
    #cpu oder mem oder beides
    #-a . all flag. outputs die nur mit vorbedingungen ausgegeben werden auch ausgeben.
    #debug flag -> block xyz not found


#in die ausgabe printen wenn ein Befehl/Block nicht gefunden wurde

#IPS engine und ips session: wenn eine einzelne IPS engine hoch ist und ein ein einzelner IPS Session wert viel mem verbruacht -> vermutlich gleiche PID



#(optinal. nicht klar wie viel man da rauslesen kann)ROLLUP   diagnose sys top-mem detail 

#Aus der Übersicht:
#memtotal, memfree, buffers, cache, active, inactive, shmem, slab
# unser top hat shared memory drin
#shared mem kann anon oder mapped sein

#sys top -> sortieren (vllt vorher addieren und mittelwert berechnen?)
#(optional) GNUPLOT für den top 5 Verbraucher, wenn es min 5 Datenpunkte gibt. Was kommt auf die Zeitachse? 

#sys top -> CPU Spalte -> sortieren
#(optional) GNUPLOT für den top 5 Verbraucher, wenn es min 5 Datenpunkte gibt. Was kommt auf die Zeitachse? 
#https://stackoverflow.com/questions/8077099/short-guide-how-to-use-gnuplot-with-python


#meminfo slab
#object size * #available objects -> Sortieren.
#einfach die ganze tabelle kopieren und ganz rechts diese zeile anfügen und danach sortieren.
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


#CPU und Interrupts
#interna S.63

#Idee: Vorschläge ausgeben lassen. Beispiel: hoher cached wert und bei miglogd mem und disk erkannt -> abstellen
#vllt eine art abgleich von symptomen und gelösten tickets. 


####################################
#Bugs

#fragmentierter Memory Verbrauch für slabs sind noch nicht plausibel

# mem conserve mode conisitency check used vs red triggert nicht.


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
    #nur als helferfunktion?
    #IPI0 bis IPI5 wichtig?
    #if bedingung err>0 -> Ausgeben!
    
#diag sys session list
#sessions nach und nach durchgehen
#was muss sonst noch in die tabelle?
#config system settings -> asymptotic enable?
#proto übersetzen für lesbarkeit -> eg. proto=6 -> TCP
#Tabelle:
#    TYP        DIRTY        NDR        NPU
#    proto=6    #hits        #hits    #hits
#    proto=7    ...
#   

#config system settings
#helferfunktion verschiedene checks werden vermutlich daten hier raus ziehen wollen.

#check sys vd 
#irgendwas mit fib. Welcher wert ist hier wichtig? 

####################################
#Bugs





#import numpy as np

import math

from tabulate import tabulate
import sys



def sys_set(sys_set_start_line, lines, end_of_block):
    print("IPS SESSIONS")
    print(lines[sys_set_start_line[0]])
    


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







def miglogd(mig_start_line, lines, end_of_block,outputfile):
    print("MIGLOGD")
    print(lines[mig_start_line[0]])
    outputfile.write("\n") 
    outputfile.write("\n") 
    outputfile.write("diagnose test application miglogd 6")
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
    print("TOP SLAB USAGE")
    print(lines[slab_start_line[0]])
    
    offset = 0
    elements = 0
    slab_block_found = 0
    head = ["Process", "active Objects", "number of Objects", "Object Size", "Objects per Slab", "pages per slab", ":", "tunables", "limit", "batch count", "shared count", ":", "slabdata", "active slabs", "number of slabs", "shared availabe", "min mem usage", "mem usage with int. fragmentation"]   

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
        data[i][16] = int(data[i][2]) * int(data[i][3])  
        
        
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
            data[i][17] = int(int(data[i][2])/elem_page * 4096)           

    
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
    


    outputfile.write("TOP SLAB USAGE")
    outputfile.write("\n")    
    outputfile.write(tabulate(data_sorted_table,headers=head,tablefmt="grid"))
    outputfile.write("\n")   
    outputfile.write("\n")     
    outputfile.write("\n")      




def mem_overview(mem_start_line, lines, end_of_block,outputfile):
    print("MEMORY OVERVIEW")
   
    print("gathered from " + lines[mem_start_line[0]])

    
    usefull_values = 8
    
    data = []
    for i in range(usefull_values):    
        data.append(["dummy"])


    for i in range(usefull_values):     
        for j in range(1):
            data[i].append("dummy")
    
    
    table_iter = 0
    for i in range(end_of_block-mem_start_line[0]-1):    
        tokens = lines[mem_start_line[0]+i].split()  

        if len(tokens)>0:
                  
            if tokens[0] == "MemTotal:":
                data[table_iter][0] = "MemTotal"
                data[table_iter][1] = str(tokens[1]) + " " + str(tokens[2])
                Memtotal = tokens[1]
                table_iter = table_iter + 1
             
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
    
    outputfile.write("MEMORY OVERVIEW")
    outputfile.write("\n")    
    outputfile.write(tabulate(data,headers=head,tablefmt="grid"))
    outputfile.write("\n") 
    outputfile.write("Free Memory: " + str(int(Memfree)/int(Memtotal)*100)+"%")       
    outputfile.write("\n")  
    outputfile.write("\n")
    outputfile.write("\n")  
    outputfile.write("\n")        
    
def shm(shm_occurances, lines, end_of_block, outputfile):
    print("CALCULATING USAGE OF /DEV/SHM")
    
    shm_tuples = []
    #name im letzten token
    #größe im vorletzten token
    for i in range(end_of_block-shm_occurances[0]-1):   
        tokens = lines[shm_occurances[0]+i+1].split()
        try:
            if len(tokens)>0:
                size = int(tokens[9])
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
    cmdb_sorted = sorted(cmdb_short, key=lambda x: int(x[1]))
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
        
            
    head = ["Name", "Size"]          
    #print(tabulate(data,headers=head,tablefmt="grid"))  

    outputfile.write("USAGE OF /DEV/SHM")
    outputfile.write("\n")    
    outputfile.write(tabulate(data,headers=head,tablefmt="grid"))
    outputfile.write("\n")   
    outputfile.write("\n")  
    outputfile.write("\n")  

def tmp(tmp_occurances, lines, end_of_block,outputfile):
    print("CALCULATING USAGE OF /DEV/TMP")


    tmp_tuples = []
    #name im letzten token
    #größe im vorletzten token
    for i in range(end_of_block-tmp_occurances[0]-1):   
        tokens = lines[tmp_occurances[0]+i+1].split()
        try:
            if len(tokens)>0:
                size = int(tokens[9])
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
    cmdb_sorted = sorted(cmdb_short, key=lambda x: int(x[1]))
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
        
            
    head = ["Name", "Size"]          
    #print(tabulate(data,headers=head,tablefmt="grid"))  


    outputfile.write("USAGE OF /DEV/TMP")
    outputfile.write("\n")    
    outputfile.write(tabulate(data,headers=head,tablefmt="grid"))
    outputfile.write("\n")   
    outputfile.write("\n")  
    outputfile.write("\n")  
    

def cmdb(cmdb_occurances, lines, end_of_block,outputfile):
    print("CALCULATING USAGE OF /DEV/CMDB")


    cmdb_tuples = []
    #name im letzten token
    #größe im vorletzten token
    for i in range(end_of_block-cmdb_occurances[0]-1):   
        tokens = lines[cmdb_occurances[0]+i+1].split()
        try:
            if len(tokens)>0:
                size = int(tokens[9])
                name = tokens[10]
                cmdb_tuples.append((name,size))
        except:
            print("jump! cmdb")
        
    print(cmdb_tuples[1])        
    
    size_numbered_processes = 0   #gumball Processes 
    cmdb_short = []
    for i in range(len(cmdb_tuples)):
        if(cmdb_tuples[i][0].isnumeric()) == True:
            size_numbered_processes = size_numbered_processes + int(cmdb_tuples[i][1])
            
        if(cmdb_tuples[i][0].isnumeric()) == False: 
              cmdb_short.append(cmdb_tuples[i])

    cmdb_short.append(("numbered_processes", int(size_numbered_processes))) 
    cmdb_sorted = sorted(cmdb_short, key=lambda x: int(x[1]))
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
        
            
    head = ["Name", "Size"]          

    outputfile.write("USAGE OF /DEV/CMDB")
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



    outputfile.write("SYS TOP / SYS TOP ALL")
    outputfile.write("\n")    
    outputfile.write(tabulate(data,headers=head,tablefmt="grid"))
    outputfile.write("\n")   
    outputfile.write("\n")  
    outputfile.write("\n")      
    

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
             
    
    
    outputfile.write("GENERAL DEVICE INFORMATION")
    outputfile.write("\n")    
    outputfile.write(tabulate(data,headers=head,tablefmt="grid"))
    outputfile.write("\n")   
    outputfile.write("\n")  
    outputfile.write("\n")          
            

def conserve(block, lines, end_of_block, outputfile):
    print("CONSERVE MODE ENTERED")
    
    
    head = ["Name, ProcessID"]   
    current_block = []
    elements = 0        #elements in block
    start = 0           #block is starting
    red = 0             #conserve mode consistency red threshold
    used = 1           #conserve mode consistency used total memory
    for i in range(end_of_block-block):    
        tokens = lines[block+i].split()

        try: 
            if len(tokens)>0:
                #print(tokens)
                if tokens[3] == "MemTotal:":
                    start = 1
                    red = 0
                    used = 1
                    current_block.append(i-1)
                    head.append(tokens[1] +" "+tokens[2])
            
                if tokens[3] == "VmallocChunk:":
                    start = 0
                    if int(red) > int(used):
                        outputfile.write("BUG detected: conserve mode threshold was calculated wrong")
                        outputfile.write("\n")                          
                        outputfile.write("used: " + str(used) + " vs red: " +str(red))   
                        outputfile.write("\n")  
                        outputfile.write("\n")
                    
                if start == 1:
                    elements = elements + 1 
                
                for j in range(len(tokens)-1):
                    #if (tokens[j] == "service=kernel" and tokens[j+1] == "conserve=on"):
                    
                    if tokens[j].split("=\"")[0] ==  "used":   
                        used = int(tokens[j].split("=\"")[1])
                        print("used " + str(used))
                        
                    if tokens[j].split("=\"")[0] ==  "red":                     
                        red = int(tokens[j].split("=\"")[1]) 
                        print("red "+ str(red))
                                                                  
                for j in range(len(tokens)-1):
                    if (tokens[j] == "mode" and tokens[j+1] == "entered\"") or (tokens[j] == "enters" and tokens[j+1] == "memory"):               
                        elements = 0 

        except:
            print("jump! conserve")



    
    
    
    data = []
    for i in range(elements):    
        data.append(["dummy"])
         
    
    print(len(current_block)+1) 
    for i in range(len(current_block)):  
        for i in range(elements):             
            data[i].append("dummy")
        

    for i in range(elements):
        tokens = lines[block + current_block[0]+i+1].split() 
        print(tokens)
        data[i][0] = tokens[3]   
        
    for j in range(len(current_block)):
        for i in range(elements):
            tokens = lines[block + current_block[j]+i+1].split() 
            data[i][j+1] = tokens[4]
                      


    outputfile.write("CONSERVE MODE ENTERED")
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



    outputfile.write("SYS TOP CPU / SYS TOP ALL CPU")
    outputfile.write("\n")    
    outputfile.write(tabulate(data,headers=head,tablefmt="grid"))
    outputfile.write("\n")   
    outputfile.write("\n")  
    outputfile.write("\n")  




        
def find_blocks(filename):


    file = open(filename,"r") 
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
    
    cmd_used_at = []
    


    
    i = 0
    for line in lines:
        
        tokens = line.split()

        len_tokens = len(tokens)
        for j in range(len(tokens)):
            
            if tokens[j] == "diag" or tokens[j] == "diagnose" or tokens[j] == "get" or tokens[j] == "fnsysctl" or tokens[j] == "exec" or tokens[j] == "show":
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
                    general_system_lines.append(i)    
        
                if tokens[t] == "sys" and tokens[t+1] == "top":
                    sys_top_lines.append(i)                       
        
                if tokens[t] == "sys" and tokens[t+1] == "top-all":
                    sys_top_lines.append(i)                       
                        
                if tokens[t] == "application" and tokens[t+1] == "miglogd" and tokens[t+2] == "6":
                    mig.append(i)                     

                if tokens[t] == "wad" and tokens[t+1] == "memory" and tokens[t+2] == "sum":
                    wad_table.append(i)
                           
                if tokens[t] == "full-configuration" and tokens[t+1] == "system" and tokens[t+2] == "settings":
                    sys_settings.append(i)                        
            
   
        i = i+1
        
        

    output_file_split = filename[:len(filename)-4]
    output_file_name = "output_" + output_file_split + ".txt" 
    outputfile = open(output_file_name,"w") 
    

    if len(general_system_lines)>0:
        end_of_block = cmd_used_at.index(general_system_lines[0])
        if end_of_block == len(cmd_used_at)-1:        
            general_system_information(general_system_lines,lines,i,outputfile)       
        else:
            general_system_information(general_system_lines,lines,cmd_used_at[end_of_block+1], outputfile)      

    if len(sys_settings)>0:       
        end_of_block = cmd_used_at.index(sys_settings[0])
        if end_of_block == len(cmd_used_at)-1:        
            settings = sys_set(sys_settings,lines,i)       
        else:
            settings = sys_set(sys_settings,lines,cmd_used_at[end_of_block+1])  

    if len(mem_overv)>0:
        end_of_block = cmd_used_at.index(mem_overv[0])
        if end_of_block == len(cmd_used_at)-1:        
            mem_overview(mem_overv,lines,i,outputfile)       
        else:
            mem_overview(mem_overv,lines,cmd_used_at[end_of_block+1], outputfile)                                
    
    if len(crashlogs)>0:
        end_of_block = cmd_used_at.index(crashlogs[0])        
        if end_of_block == len(cmd_used_at)-1:
            conserve(crashlogs[0],lines,i, outputfile)
        else:
            conserve(crashlogs[0],lines,cmd_used_at[end_of_block+1], outputfile)            


    if len(sys_top_lines)>0:
        for j in range(len(sys_top_lines)):                     
            end_of_block = cmd_used_at.index(sys_top_lines[j])
            if end_of_block == len(cmd_used_at)-1:            
                sys_top(sys_top_lines[j],lines,i,outputfile)
            else:
                sys_top(sys_top_lines[j],lines,cmd_used_at[end_of_block+1], outputfile)      



    if len(cmdb_occurances)>0:
        end_of_block = cmd_used_at.index(cmdb_occurances[0])
        if end_of_block == len(cmd_used_at)-1:        
            cmdb(cmdb_occurances,lines,i,outputfile)
        else:
            cmdb(cmdb_occurances,lines,cmd_used_at[end_of_block+1], outputfile)        
        
    if len(tmp_occurances)>0:
        end_of_block = cmd_used_at.index(tmp_occurances[0])
        if end_of_block == len(cmd_used_at)-1:        
            tmp(tmp_occurances,lines,i,outputfile)
        else:
            tmp(tmp_occurances,lines,cmd_used_at[end_of_block+1], outputfile)        
        
    if len(shm_occurances)>0:
        end_of_block = cmd_used_at.index(shm_occurances[0])
        if end_of_block == len(cmd_used_at)-1:        
            shm(shm_occurances,lines,i,outputfile)
        else:
            shm(shm_occurances,lines,cmd_used_at[end_of_block+1], outputfile)        
     
    #diagnose hardware sysinfo slab   
    if len(slabinfo)>0:
        end_of_block = cmd_used_at.index(slabinfo[0])
        if end_of_block == len(cmd_used_at)-1:        
            slab(slabinfo,lines,i,outputfile)
        else:
            slab(slabinfo,lines,cmd_used_at[end_of_block+1], outputfile)        
    
    if len(slabinfo) == 0:    
        outputfile.write("diagnose hardware sysinfo slab not found") 

    #get ips session
    if len(ips_session)>0:
        end_of_block = cmd_used_at.index(ips_session[0])
        if end_of_block == len(cmd_used_at)-1:        
            ips_s(ips_session,lines,i,outputfile)
        else:
            ips_s(ips_session,lines,cmd_used_at[end_of_block+1], outputfile)        
    
    if len(ips_session) == 0:
        outputfile.write("get ips session not found")   
        
          
    #diagnose test application miglogd 6
    if len(mig)>0:
        end_of_block = cmd_used_at.index(mig[0])
        if end_of_block == len(cmd_used_at)-1:        
            miglogd(mig,lines,i,outputfile)
        else:
            miglogd(mig,lines,cmd_used_at[end_of_block+1], outputfile)        

    if len(mig) == 0:
        outputfile.write("diagnose test application miglogd 6 not found") 

    #diagnose wad memory sum
    if len(wad_table)>0:
        end_of_block = cmd_used_at.index(wad_table[0])
        if end_of_block == len(cmd_used_at)-1:        
            wad_t(wad_table,lines,i,outputfile)
        else:
            wad_t(wad_table[0],lines,cmd_used_at[end_of_block+1], outputfile)        

    if len(wad_table) == 0:
        outputfile.write("diagnose wad memory sum not found or empty")         


##########################
############## CPU ######
##########################

    if len(sys_top_lines)>0:
        for j in range(len(sys_top_lines)):                     
            end_of_block = cmd_used_at.index(sys_top_lines[j])
            if end_of_block == len(cmd_used_at)-1:            
                sys_top_cpu(sys_top_lines[j],lines,i,outputfile)
            else:
                sys_top_cpu(sys_top_lines[j],lines,cmd_used_at[end_of_block+1], outputfile)        







    outputfile.close()
   
   
   
#if __name__ == "__main__":
#    print(f"Arguments count: {len(sys.argv)}")
#    for i, arg in enumerate(sys.argv):
#        print(f"Argument {i:>6}: {arg}")
#
#    find_blocks(sys.argv[1])

find_blocks("conserve_thresh_bug.txt")


