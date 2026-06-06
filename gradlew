#!/usr/bin/env sh

# Create gradlew script for GitHub Actions compatibility
# This is a minimal wrapper to trigger gradle build tool

# Attempt to set APP_HOME
# Resolve links: $0 may be a link
PRG="$0"
# Need this for relative symlinks.
while [ -h "$PRG" ] ; do
    ls=`ls -ld "$PRG"`
    link=`expr "$ls" : '.*-> \(.*\)$'`
    if expr "$link" : '/.*' > /dev/null; then
        PRG="$link"
    else
        PRG=`dirname "$PRG"`"/$link"
    fi
done
SAVED="`pwd`"
cd "`dirname \"$PRG\"`/" >/dev/null
APP_HOME="`pwd`"
cd "$SAVED" >/dev/null

# Execute gradle
exec java -cp "$APP_HOME/app" org.gradle.wrapper.GradleWrapperMain "$@"
