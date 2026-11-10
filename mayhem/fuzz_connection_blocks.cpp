/*
    Fuzz target: yojimbo::Connection::ProcessPacket() over reliable-ordered channels whose
    maxBlockSize is not a multiple of blockFragmentSize (the stock fuzz configs all use
    multiples). Input framing is that of fuzz/fuzz_connection.cpp:
    [u8 config selector]([u16 LE length][packet])*.
*/

#include "yojimbo.h"
#include "fuzz_messages.h"

#include <stdint.h>
#include <string.h>

using namespace yojimbo;

static const int NumConfigs = 6;

// Reliable-ordered channels whose maxBlockSize is NOT a multiple of blockFragmentSize, so the
// last fragment slot of the reassembly buffer is shorter than blockFragmentSize.
static void make_config( uint8_t selector, ConnectionConfig & config )
{
    config.numChannels = 1;
    config.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    switch ( selector % NumConfigs )
    {
        case 0: config.channel[0].maxBlockSize = 1100; config.channel[0].blockFragmentSize = 500; break;
        case 1: config.channel[0].maxBlockSize = 2500; config.channel[0].blockFragmentSize = 1024; break;
        case 2: config.channel[0].maxBlockSize = 1000; config.channel[0].blockFragmentSize = 300; break;
        case 3: config.channel[0].maxBlockSize = 1025; config.channel[0].blockFragmentSize = 1024; break;
        case 4: config.channel[0].maxBlockSize = 3000; config.channel[0].blockFragmentSize = 700; break;
        case 5:
            config.numChannels = 2;
            config.channel[1].type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;
            config.channel[0].maxBlockSize = 1100; config.channel[0].blockFragmentSize = 500;
            break;
    }
}

static bool g_init = false;

static void ensure_init()
{
    if ( !g_init )
    {
        InitializeYojimbo();
        // The message-leak check in ~MessageFactory reports at ERROR level before
        // calling exit(1); the default log level (NONE) would swallow the report.
        yojimbo_log_level( YOJIMBO_LOG_LEVEL_ERROR );
        g_init = true;
    }
}

extern "C" int LLVMFuzzerTestOneInput( const uint8_t * data, size_t size )
{
    ensure_init();

    if ( size < 1 )
        return 0;

    // first byte selects the connection config
    ConnectionConfig config;
    make_config( data[0], config );
    size_t pos = 1;

    FuzzMessageFactory messageFactory( GetDefaultAllocator() );
    Connection connection( GetDefaultAllocator(), messageFactory, config, 100.0 );

    // The BitReader reads whole 32-bit words, so it may touch up to 3 bytes past the packet
    // end. Real receive paths always have slack; mirror that with a padded, zeroed buffer.
    static uint8_t buf[ 8 * 1024 + 16 ];
    if ( config.maxPacketSize + 16 > (int) sizeof( buf ) )
        return 0;

    const int maxPacket = config.maxPacketSize;
    const int MAX_PACKETS = 64;

    double time = 100.0;
    uint16_t sequence = 0;

    for ( int p = 0; p < MAX_PACKETS && pos < size; ++p )
    {
        // read a 2-byte length prefix (missing bytes read as zero)
        size_t len = data[pos];
        pos++;
        if ( pos < size )
        {
            len |= (size_t) data[pos] << 8;
            pos++;
        }

        size_t avail = size - pos;
        if ( len > avail )
            len = avail;                 // last packet takes the remainder

        int packetBytes = (int) ( len > (size_t) maxPacket ? (size_t) maxPacket : len );

        if ( packetBytes > 0 )
        {
            memset( buf, 0, (size_t) packetBytes + 16 );
            memcpy( buf, data + pos, (size_t) packetBytes );
            connection.ProcessPacket( NULL, sequence, buf, packetBytes );
        }

        pos += len;
        sequence++;

        time += 0.1;
        connection.AdvanceTime( time );

        // drain anything delivered so messages don't accumulate across packets
        for ( int channelIndex = 0; channelIndex < config.numChannels; ++channelIndex )
        {
            while ( Message * message = connection.ReceiveMessage( channelIndex ) )
                messageFactory.ReleaseMessage( message );
        }
    }

    return 0;
}

