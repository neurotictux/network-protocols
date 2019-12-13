#include <stdlib.h>
#include <pcap.h>

int main()
{
  const int packet_size = 40; // change the value for real size of your packet
  char *packet = (char *)malloc(packet_size);
  pcap_t *handle = NULL;
  char errbuf[PCAP_ERRBUF_SIZE], *device = NULL;
  if ((device = pcap_lookupdev(errbuf)) == NULL)
  {
    fprintf(stderr, "Error lookup device", device, errbuf);
    exit(1);
  }
  if ((handle = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL)
  {
    fprintf(stderr, "ERRO: %s\n", errbuf);
    exit(1);
  }
  // here you have to write your packet bit by bit at packet
  int result = pcap_inject(handle, packet, packet_size);
}