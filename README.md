# SMP Backend

### About

This is a backend for the [smp](https://github.com/Quartzy0/smp) project
which aims to provide a Spotify client that does not require an account on
the client side. This project makes use of a modified version of [librespotc](https://github.com/ejurgensen/librespot-c)
and Spotify's web API for interfacing with Spotify.

The communication between the client and this backend is done over TCP sockets
as opposed to http/https. Since the client is not providing the server with any
identifiable information, encryption is not necessary.

### Setup

#### Build dependencies

- libevent-dev
- libgcrypt20-dev
- libcurl4-gnutls-dev
- libjson-c-dev
- libprotobuf-c-dev
- openssl
- pthread

To run the backend simply run the executable with the account details of the accounts
you wish to be used by it. Note, however, that these account must be premium ones.
```shell
smp-backend <username> <password> ...
```
You can use multiple accounts by specifying all of their usernames and passwords in the arguments
in the order of username followed by password. Alternatively, you may also store these details in a
file and provide only the file path as an argument to the executable. The file must have the following format:
```
<email> <password> <username>
<email> <password> <username>
...
```

### Protocol

As mentioned above, the backend and the client communicate over TCP sockets. Once a connection is made,
no further authentication is required.

#### Serverbound

##### General packet structure for serverbound packets

```
Byte    -   Description
0       -   Request type (music data, music info, etc...)
1 - ... -   Request data (varies per request)
```

##### Request types

- MUSIC_DATA - 0
- MUSIC_INFO - 1
- PLAYLIST_INFO - 2
- ALBUM_INFO - 3
- [RECOMMENDATIONS](#recommendations-request-type) - 4

All request types except for RECOMMENDATIONS follow the same structure. The request data is the 22 character
spotify ID. For example, if the was 0 (MUSIC_DATA), the request data could be `4cOdK2wGLETKBW3PvgPWqT`, a spotify
track id. For information regarding the responses each of these request types yields, check the [responses](#responses)
section.

###### RECOMMENDATIONS request type

The request data for the recommendations request type differs from the rest because multiple IDs may be required.
As such, the structure of the request data of a recommendations packet is as such:

```
Byte    -   Description
0       -   Number of IDs representing seed tracks
1       -   Number of IDs representing seed artists
2 - ... -   bytes[0] + bytes[1] number of 22 character spotify IDs 
```

#### Clientbound

All responses are cached on the server side to minimize the amount of communication with the spotify servers and
improve response time.

##### General packet structure for clientbound packets

```
Byte    -   Description
0       -   Response status (success is 0, error, etc.)
1 - 9   -   Message length (size_t)
9 - ... -   Response body
```

##### Response status

The response status indicated very broadly the type of error that occurred, if any. On success,
this value will always be 0. However, if an error does happen, the response status will be non-zero
and the response body will contain a more detailed error message.

##### Responses

All responses other than [MUSIC_DATA](#music_data) function as a kind of proxy between the client and Spotify's Web API,
providing the benefit of not requiring any kind of authentication on the client side. These are their equivalent HTTP requests:

- [MUSIC_INFO](https://developer.spotify.com/documentation/web-api/reference/#/operations/get-track) - `https://api.spotify.com/v1/tracks/{id}`
- [PLAYLIST_INFO](https://developer.spotify.com/documentation/web-api/reference/#/operations/get-playlist) - `https://api.spotify.com/v1/playlists/{id}`
- [ALBUM_INFO](https://developer.spotify.com/documentation/web-api/reference/#/operations/get-an-album) - `https://api.spotify.com/v1/albums/{id}`
- [RECOMMENDATIONS](https://developer.spotify.com/documentation/web-api/reference/#/operations/get-recommendations) - `https://api.spotify.com/v1/recommendations?seed_tracks={ids}&seed_artists={ids}&limit=30`

###### MUSIC_DATA

The response body of this type of response will be vorbis audio data of the song requested. This may be parsed on the client side using
a library like libvorbis or written to a file and played with a program like mpv.

