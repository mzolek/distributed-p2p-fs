// Authors: Krzysztof Żyndul, Marcin Żołek

package main

import (
	"bytes"
	"fmt"
	"image"
	"image/jpeg"
	"os"
)

type Node struct {
	Hash     []byte
	Type     byte
	Value    []byte
	Children []*Node
	Name     string
}

type File struct {
	Name string
	Data []byte
}

type Folder struct {
	Name        string
	Files       []*File
	Directories []*Folder
}

func newNode(hash []byte, nodeType byte, value []byte, name string) *Node {
	hashCopy := make([]byte, len(hash))
	copy(hashCopy, hash)

	var valueCopy []byte
	if value != nil {
		valueCopy = make([]byte, len(value))
		copy(valueCopy, value)
	}

	return &Node{
		Hash:     hashCopy,
		Type:     nodeType,
		Children: []*Node{},
		Value:    valueCopy,
		Name:     name,
	}
}

func (n *Node) AddChild(child *Node) {
	n.Children = append(n.Children, child)
}

func (file *File) String() string {
	return fmt.Sprintf("File{Name: %s, Size: %d bytes}", file.Name, len(file.Data))
}

func (folder *Folder) String() string {
	return fmt.Sprintf("Folder{Name: %s, Files: %d, Directories: %d}", folder.Name, len(folder.Files), len(folder.Directories))
}

func processNode(message Message, hashToNodeMap map[[32]byte]*Node, needed map[[32]byte]struct{}) {
	node := hashToNodeMap[getHash(message)]
	datumType := getDatumType(message)
	data := getDatumValue(message)

	node.Type = datumType

	switch node.Type {
	case Chunk:
		node.Value = make([]byte, len(data))
		copy(node.Value, data)
	case Directory:
		for i := 0; i < len(data); i += 64 {
			if i+64 > len(data) {
				break
			}
			filename := string(data[i:(i + 32)])
			hash := [32]byte(data[(i + 32):(i + 64)])
			child := newNode(hash[:], 0, nil, filename)
			node.AddChild(child)
			needed[hash] = struct{}{}
			hashToNodeMap[hash] = child
		}
	case Big:
		for i := 0; i < len(data); i += 32 {
			if i+32 > len(data) {
				break
			}
			hash := [32]byte(data[i:(i + 32)])
			child := newNode(hash[:], 0, nil, node.Name)
			node.AddChild(child)
			needed[hash] = struct{}{}
			hashToNodeMap[hash] = child
		}
	default:
		fmt.Println("Unknown node type:", node.Type)
		return
	}
}

func printFileSystem(folder *Folder, indent string) {
	fmt.Println(indent + folder.String())
	for _, file := range folder.Files {
		fmt.Println(indent + "--" + file.String())
	}
	for _, subFolder := range folder.Directories {
		printFileSystem(subFolder, indent+"--")
	}
}

func printTextFile(file *File) {
	fmt.Println("Text File: " + file.Name)
	content := string(file.Data)
	if len(content) > 100 {
		content = content[:100] + "..."
	}
	fmt.Println("Content: " + content)
}

func saveImageTooDisk(file *File, path string) error {

	fmt.Printf("Saving %s.\n", path)

	img, _, err := image.Decode(bytes.NewReader(file.Data))
	if err != nil {
		return fmt.Errorf("Error decoding image data for file %s: %v", file.Name, err)
	}
	fmt.Printf("Saving %s.\n", path)

	outFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("Error creating file %s: %v", path, err)
	}
	defer outFile.Close()

	var opts jpeg.Options
	opts.Quality = 100
	err = jpeg.Encode(outFile, img, &opts)
	if err != nil {
		return fmt.Errorf("Error encoding image data for file %s: %v", file.Name, err)
	}
	fmt.Printf("File %s saved successfully.\n", path)
	return nil
}

func buildFileSystem(node *Node) (*Folder, error) {
	dir := &Folder{
		Name:        node.Name,
		Files:       []*File{},
		Directories: []*Folder{},
	}

	for _, child := range node.Children {
		switch child.Type {
		case Directory:
			subDir, err := buildFileSystem(child)
			if err != nil {
				fmt.Printf("Error building filesystem for directory %s: %v\n", child.Name, err)
				return nil, err
			}
			dir.Directories = append(dir.Directories, subDir)

		case Big:
			isBigDirectory := isBigDirectory(child)

			if isBigDirectory == 1 {
				subDir, err := flattenBigDirectory(child)
				if err != nil {
					fmt.Printf("Error flattening big directory %s: %v\n", child.Name, err)
					return nil, err
				}
				if subDir != nil {
					dir.Directories = append(dir.Directories, subDir)
				}
			} else if isBigDirectory == -1 {
				data := flattenBigFile(child)
				file := &File{
					Name: child.Name,
					Data: data,
				}
				dir.Files = append(dir.Files, file)
			} else if isBigDirectory == 0 {
				return nil, fmt.Errorf("mixed content in big %s", child.Name)
			}
		case Chunk:
			file := &File{
				Name: child.Name,
				Data: child.Value,
			}
			dir.Files = append(dir.Files, file)
		default:
			fmt.Printf("Unknown child type %d in directory %s\n", child.Type, node.Name)
			// return nil, fmt.Errorf("unknown child type %d in directory %s", child.Type, node.Name)
		}
	}
	return dir, nil
}

func flattenBigDirectory(node *Node) (*Folder, error) {
	dir := &Folder{
		Name:        node.Name,
		Files:       []*File{},
		Directories: []*Folder{},
	}

	for _, child := range node.Children {
		switch child.Type {
		case Chunk:
			// Cannot happened we check isBigDirectory before
			return nil, nil
		case Big:
			subResult, err := flattenBigDirectory(child)
			if err != nil {
				fmt.Printf("Error flattening big directory %s: %v\n", child.Name, err)
				return nil, err
			}
			if subResult != nil {
				dir.Directories = append(dir.Directories, subResult.Directories...)
				dir.Files = append(dir.Files, subResult.Files...)
			}

		case Directory:
			subDir, err := buildFileSystem(child)
			if err != nil {
				fmt.Printf("Error building filesystem for directory %s: %v\n", child.Name, err)
				return nil, err
			}
			dir.Directories = append(dir.Directories, subDir)
		default:
		}
	}
	return dir, nil
}

func flattenBigFile(node *Node) []byte {
	var data []byte
	for _, child := range node.Children {
		switch child.Type {
		case Chunk:
			data = append(data, child.Value...)
		case Big:
			childData := flattenBigFile(child)
			data = append(data, childData...)
		case Directory:
			// Cannot happened we check isBigDirectory before
			return nil
		default:
			return nil
		}
	}
	return data
}

// -1 file, 0 undefined/mixed, 1 directory
func isBigDirectory(node *Node) int {
	if node.Type == Directory {
		return 1
	}

	var result int
	first := true

	for _, child := range node.Children {
		var subResult int
		switch child.Type {
		case Big:
			subResult = isBigDirectory(child)
			if subResult == 0 {
				return 0
			}
		case Chunk:
			subResult = -1
		case Directory:
			subResult = 1
		default:
			fmt.Printf("Unknown child type %d in big %s\n", child.Type, node.Name)
			subResult = 0
		}

		if first {
			result = subResult
			first = false
		} else if subResult != result {
			return 0
		}
	}

	return result
}
