package graph

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/emicklei/dot"
)

var serviceMapGraph *ServiceMapGraph

type ServiceMapGraph struct {
	graph *dot.Graph
	nodes map[string]*dot.Node
	edges map[string]*dot.Edge // key is from-to node
	file  *os.File
}

func generateFileName() string {
	return "service_map" + time.Now().Format("2006-01-02T15:04:05") + ".dot"
}

func (smap *ServiceMapGraph) writeToFile() {
	fileName := generateFileName()
	file, err := os.Create(fileName)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	smap.graph.Write(file)
	smap.file = file
}

func init() {
	initServiceMapGraph()
	http.HandleFunc("/graph", Advertise())
}

func AddEdge(from, to string, weight uint32) {
	fmt.Println("AddEdge", from, to, weight)
	fromNode := serviceMapGraph.nodes[from]
	toNode := serviceMapGraph.nodes[to]
	if fromNode == nil || toNode == nil {
		log.Println("Node not found:", from, to)
		return
	}

	serviceMapGraph.graph.Edge(*fromNode, *toNode).Attr("weight", weight)
}

func AddNodes(names ...string) {
	for _, name := range names {
		dotNode := serviceMapGraph.graph.Node(name)
		serviceMapGraph.nodes[name] = &dotNode
	}
}

func initServiceMapGraph() {
	serviceMapGraph = &ServiceMapGraph{
		graph: dot.NewGraph(dot.Directed),
		nodes: make(map[string]*dot.Node),
		edges: make(map[string]*dot.Edge),
	}
}

func Advertise() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		serviceMapGraph.writeToFile()

		if serviceMapGraph.file == nil {
			log.Println("No DOT file to convert to PNG")
			return
		}

		// Set the content type header
		w.Header().Set("Content-Type", "text/plain")

		// Write the DOT content as the response
		serviceMapGraph.graph.Write(w)
	}
}
