/*
** Copyright (C) 2009-2023 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2023 Champ Clark III <cclark@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* This is a example program of how "offload" works.   The "offload"
 keyword allows customer written programs to do analysis and report back
 to Sagan what it found.  Your program simply needs to accept inbound
 web connection (POST) and return "true" (fire a event) or "false"
 (don't fire).

To build this program, type:

$ go mod init simple-offload-program
$ go mod tidy
$ go build
$ ./simple-offload-program

By default,  it listens on TCP/4444.  You can then write a signature that can all your
program as part of the detection process.  For example:

alert any $EXTERNAL_NET any -> $HOME_NET any (msg:"Test OFFLOAD signature"; content: "testing"; offload: "http://127.0.0.1:4444"; classtype:misc-attack; sid:10000; rev:1;)

*/

package main

import (
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
)

type C struct {
        Counter int
        }

var CM = C{}
		
/********************************************************/
/* Main - Setup a webserver to listen for POST requests */
/********************************************************/

func main() {

	var err error

	HTTP_Listen := ":4444" /* Port to listen on */
	gin.SetMode("debug")   /* 'debug', 'release' or 'test' */

	router := gin.Default()

	router.POST("/testme", Process_Data) /* URI to accept POST requests */

	log.Printf("Listening for unencrypted traffic on %s.", HTTP_Listen)
	err = router.Run(HTTP_Listen)

	if err != nil {
		log.Fatalf("Cannot bind to %s\n", HTTP_Listen)
	}
}

/*****************************************************/
/* Process_Data - This is where your logic would sit */
/*****************************************************/

func Process_Data(c *gin.Context) {

	CM.Counter++

	log.Printf("** Logs Received: %v\n", CM.Counter)

	var jsondata []uint8

	jsondata, _ = c.GetRawData()

	log.Printf("Got this data from Sagan: %s\n", string(jsondata))

	/* You would do your processing and magic here! */

	c.Data(http.StatusOK, "text/html", []byte("true")) /* return "true" or "false" */

}
