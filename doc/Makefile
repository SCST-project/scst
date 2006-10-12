COMMAND=linuxdoc --backend=

SOURCE_NAME=scst_pg

SOURCE=$(SOURCE_NAME).sgml

default: html txt pdf

all: html txt pdf tex dvi ps info lyx rtf

txt: $(SOURCE_NAME).txt

html: $(SOURCE_NAME).html

tex: $(SOURCE_NAME).tex

dvi: $(SOURCE_NAME).dvi

ps: $(SOURCE_NAME).ps

pdf: $(SOURCE_NAME).pdf

info: $(SOURCE_NAME).info

lyx: $(SOURCE_NAME).lyx

rtf: $(SOURCE_NAME).rtf

$(SOURCE_NAME).txt: $(SOURCE)
	$(COMMAND)txt $(SOURCE)

$(SOURCE_NAME).html: $(SOURCE)
	$(COMMAND)html --split=0 $(SOURCE)

$(SOURCE_NAME).tex: $(SOURCE)
	$(COMMAND)latex -o tex $(SOURCE)

$(SOURCE_NAME).dvi: $(SOURCE)
	$(COMMAND)latex -o dvi $(SOURCE)

$(SOURCE_NAME).ps: $(SOURCE)
	$(COMMAND)latex -o ps $(SOURCE)

$(SOURCE_NAME).pdf: $(SOURCE)
	$(COMMAND)latex -o pdf $(SOURCE)

$(SOURCE_NAME).info: $(SOURCE)
	$(COMMAND)info $(SOURCE)

$(SOURCE_NAME).lyx: $(SOURCE)
	$(COMMAND)lyx $(SOURCE)

$(SOURCE_NAME).rtf: $(SOURCE)
	$(COMMAND)rtf $(SOURCE)

clean:
	rm -f *.txt *.html *.tex *.dvi *.ps *.pdf *.info *.lyx *.rtf

extraclean: clean

.PHONY: all default html txt pdf tex dvi ps info lyx rtf clean extraclean
