## I will use this to describe the csv.

##### domainName: Name of the domain. So much can be done with reputation stuff. Just write the functions and add to existing script.
##### count: Honestly... the most effective feature. Data Size / Entropy = Count. 

## Word Magic: 
### For every item below there are 4 columns.
#### countUnique
#### percentageUnique
#### modeCount
#### percentageMode

##### temp0 = subdomain array: Super important for DNS, less likely to be used for HTTP because there are so many other places to hide data. 
##### temp1 = user agent array: Unlikely to be used by anyone, but it could happen. 
##### temp2 = uri array: Super important for HTTP, URI encoded. 

## Math Magic: 
### For every item in this list, there are 9 columns for each statistics function returned
#### countUnique
#### percentageUnique #Should I add in modeCount and percentageMode? 
#### average
#### minimum
#### maximum
#### entropyStat
#### variationStat
#### skewStat
#### kurtosisStat

##### temp_0 = delta time list: Stats from an array of the time differences between connections... a poor man's time series analysis. There are much better ways to do this most likely, for now, most likely effective. 
##### magicDurationArray = connection durations: Stats from an array of the connection lengths. File under, possibly important. 
### TIME TO DO: Actual time series analysis
##### magicOrigBytesArray = bytes sent: Important
##### magicRespBytesArray = bytes received: Ditto and #yes
##### magicOrigPacketsArray = packets sent: Ditto and #yes
##### magicOrigIpBytesArray = ip bytes sent: Ditto and #yes
##### magicRespPacketsArray = packets recieved: Ditto and #yes
##### magicRespIpBytesArray = ip bytes recieved: Ditto and #yes 
#### Bytes To Do: Various Producer/Consumer Ratios
##### temp_2 = uri length: Length of the URI, longer = sketchier.
##### temp_3 = uri depth:  Stats from array of directory depths in URI.  
##### temp_4 = uri entropy: Stats from array of uri entropy, can be significantly optimized. 
### URI TO DO: Longest common substring stuff, URI hexadecimal count, entropy in final subdirectory.
##### temp_5 = agent length: #unlikely to matter, #unlikely to matter
##### temp_6 = agent depth: #unlikely to matter, #unlikely to matter
##### temp_7 = agent entropy: #unlikely to matter, recommend ignore
