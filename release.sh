#!/bin/sh
#
# Release script
#

LIBRARY="two-factor-auth"
LOCAL_DIR="$HOME/svn/local/$LIBRARY"

#############################################################
# check ChangeLog

head -1 changelog.txt | fgrep '?' > /dev/null 2>&1
if [ $? -ne 1 ]; then
	echo "No question-marks (?) can be in the ChangeLog top line."
	head -1 src/main/javadoc/doc-files/changelog.txt
	exit 1
fi

#############################################################
# check for not commited files:

git status | grep 'nothing to commit'
if [ $? -ne 0 ]; then
	/bin/echo "Files not checked-in"
	git status
	exit 1
fi

#############################################################
# check maven settings

grep oss-embuc $HOME/.m2/settings.xml > /dev/null 2>&1
if [ $? -ne 0 ]; then
    /bin/echo "Can't find sonatype info in the maven settings.xml file"
    exit 1
fi

#############################################################

release=`grep version pom.xml | grep SNAPSHOT | head -1 | cut -f2 -d\> | cut -f1 -d\-`

/bin/echo ""
/bin/echo ""
/bin/echo ""
/bin/echo "------------------------------------------------------- "
/bin/echo -n "Enter release number [$release]: "
read rel
if [ "$rel" != "" ]; then
	release=$rel
fi

#############################################################
# check docs:

ver=`head -1 changelog.txt | cut -f1 -d:`
if [ "$release" != "$ver" ]; then
	echo "Change log top line version seems wrong:"
	head -1 changelog.txt
	exit 1
fi

grep -q $release README.md
if [ $? != 0 ]; then
	echo "Could not find $release in README.md"
	exit 1
fi

#############################################################
# run tests

mvn test || exit 1

#############################################################

/bin/echo ""
/bin/echo -n "Enter the GPG pass-phrase: "
read gpgpass

GPG_ARGS="-Darguments=-Dgpg.passphrase=$gpgpass -Dgpg.passphrase=$gpgpass -DgpgPhase=verify"

tmp="/tmp/release.sh.$$.t"
touch $tmp
gpg --passphrase $gpgpass -s -u 07429096BC2AA85E $tmp > /dev/null 2>&1
if [ $? -ne 0 ]; then
    /bin/echo "Passphrase incorrect"
    exit 1
fi
rm -f $tmp*

#############################################################

/bin/echo ""
/bin/echo "------------------------------------------------------- "
/bin/echo "Releasing version '$release'"
sleep 3

#############################################################
# releasing to sonatype

/bin/echo ""
/bin/echo ""
/bin/echo -n "Should we release to sonatype [y]: "
read cont
if [ "$cont" = "" -o "$cont" = "y" ]; then
    mvn -Prelease release:clean || exit 1
    mvn $GPG_ARGS -Prelease release:prepare || exit 1
    mvn $GPG_ARGS -Prelease release:perform || exit 1

    /bin/echo ""
    /bin/echo ""
fi