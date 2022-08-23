FROM redis:7.0-alpine
COPY tests/ssl/redis/redis.crt /tmp.ssl/
COPY tests/ssl/redis/redis.key /tmp.ssl/
COPY tests/ssl/ca/ca.crt /tmp.ssl/ca.crt
RUN chown -R redis:redis /tmp.ssl

COPY docker/_scripts/redis/redis.conf /usr/local/etc/redis/redis.conf

ENTRYPOINT ["redis-server"]
CMD ["/usr/local/etc/redis/redis.conf"]