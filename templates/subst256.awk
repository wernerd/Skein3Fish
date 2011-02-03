BEGIN { d=0; j=0; drev = 7 ;linesPerRound=2; line=0; algo="R_256_"; words=2}
/^ *Mix/ {
    pattern=algo d "_" j
    gsub(", [0-9][0-9]", ", " pattern )
    gsub(", [0-9]", ", " pattern )
    print $0
    line++
    if (line == linesPerRound) {
	d=(d+1)%8
	line = 0
    }
    j=(j+1)%words
    next
}

/^ *UnMix/ {
    pattern=algo drev "_" j
    gsub(", [0-9][0-9]", ", " pattern )
    gsub(", [0-9]", ", " pattern )
    print $0
    line++
    if (line == linesPerRound) {
	drev--
	line = 0
    }
    if (drev < 0) {
	drev = 7
    }
    j=(j+1)%words
    next
}

{print $0}
