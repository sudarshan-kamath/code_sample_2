lftp -u "$FTP_USER","$FTP_PASS" ftp://$FTP_HOST \
  -e "get $REMOTE_PATH -o -; bye" | tshark -r -
