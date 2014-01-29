#!/usr/bin/awk

# call: awk params.txt plaintext+salt.txt
# prints  a parameter line after every second line (salt).

BEGIN {
    paramCount=0
}

{
  if (FILENAME ~ /params.txt/) {
      params[paramCount] = $0 
      paramCount++
  } else {
    print $0
    if ((FNR % 2) == 0) { 
      print params[FNR - 1 % paramCount]
    }
  }
}
