FROM tomcat:8.5.84-jdk8-corretto
RUN yum -y install wget unzip &&  yum -y clean all  && rm -rf /var/cache
RUN wget https://github.com/sectooladdict/wavsep/releases/download/wavsep-v1.5-war/wavsep-v1.5-war.zip -O /tmp/wavsep.zip && cd /tmp ; unzip wavsep.zip ; rm wavsep.zip; mv wavsep.war /usr/local/tomcat/webapps

