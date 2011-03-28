SRCS = $(wildcard *.sgml)

TXTS = $(SRCS:.sgml=.txt)
GTXTS = $(SRCS:.sgml=.gtxt)
PDFS = $(SRCS:.sgml=.pdf)
HTMLS = $(SRCS:.sgml=.html)
RTFS = $(SRCS:.sgml=.rtf)

COMMAND=linuxdoc --backend=

all: txt pdf html

txt: $(TXTS)

gtxt: $(GTXTS)

pdf: $(PDFS)

html: $(HTMLS)

rtf: $(RTFS)

%.txt: %.sgml
	$(COMMAND)txt -f $(<)

%.gtxt: %.sgml
	$(COMMAND)txt $(<)

%.html: %.sgml
	$(COMMAND)html --split=0 $(<)

%.pdf: %.sgml
	$(COMMAND)latex -o pdf $(<)

%.rtf: %.sgml
	$(COMMAND)rtf $(<)

clean:
	rm -f *.txt *.html *.tex *.dvi *.ps *.pdf *.info *.lyx *.rtf

extraclean: clean
	rm -f *.orig *.rej

.PHONY: all default html txt gtxt pdf tex dvi ps info lyx rtf check clean extraclean
