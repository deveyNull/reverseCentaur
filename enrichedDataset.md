## I will use this to describe the csv. It's kinda stream of consciousness now, but it will become prettier. 

##### [0]: domainName 
##### [1]: count, count # just in general useful for all of this... if you use total values for things like bytes or packets io, should be used to scale results.

## Word Magic: return([countUnique, percentageUnique, modeCount, percentageMode]) 
### For every item below there are 4 columns.
##### [2-6] temp0, subdomain array #super important for DNS, less so for http
##### [6-11] temp1, agent array #unlikely, ignore
temp2, uri array #super important for http, encoded in URI

## Math Magic: (return([countUnique, percentageUnique, average, minimum, maximum, entropyStat, variationStat, skewStat, kurtosisStat])
### For every item in this list, there are 9 columns for each statistics function returned

##### temp_0, delta time list # very important, periodicity?
##### magicDurationArray, durations #possibly important
##### magicOrigBytesArray, bytes sent #yes * maybe something can be done with ratios here
##### magicRespBytesArray, bytes received #yes
##### magicOrigPacketsArray, packets sent #yes
##### magicOrigIpBytesArray, ip bytes sent #yes
##### magicRespPacketsArray, packets recieved #yes
##### magicRespIpBytesArray, ip bytes recieved #yes *  maybe something can be done with ratios here
##### temp_2, uri length #important
##### temp_3, uri depth #important
##### temp_4, uri entropy #important
##### temp_5, agent length #unlikely to matter, #unlikely to matter
##### temp_6, agent depth #unlikely to matter, #unlikely to matter
##### temp_7, agent entropy #unlikely to matter, recommend ignore
