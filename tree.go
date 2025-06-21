// Authors: Krzysztof Żyndul, Marcin Żołek

package main

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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

func saveFileSystem(folder *Folder, basePath string) {

	// absBasePath, err := filepath.Abs(basePath)
	// fmt.Printf("DEBUG basePath: '%s', absBasePath: '%s'\n", basePath, absBasePath)
	fmt.Printf("DEBUG basePath: '%s'\n", basePath)

	// if err != nil {
	// 	fmt.Printf("error getting absolute path: %v\n", err)
	// 	return
	// }
	currentPath := filepath.Join(basePath, folder.Name)

	fmt.Printf("Is path basePath valid %t: \n", fs.ValidPath(basePath))
	// fmt.Printf("Is path absBasePath valid %t: \n", fs.ValidPath(absBasePath))
	fmt.Printf("Is path currentPath valid: %t: \n", fs.ValidPath(currentPath))
	fmt.Printf("Is path folder.Name valid: %t: \n", fs.ValidPath(folder.Name))

	// fmt.Printf("DEBUG currentPath: %s, absolutePath: %s\n", currentPath, absBasePath)
	fmt.Printf("Creating folder: '%s'\n", folder.Name)
	if folder.Name == "" {
		fmt.Println("error: folder name is empty")
		return
	}

	if err := os.MkdirAll(currentPath, 0755); err != nil && !os.IsExist(err) {
		fmt.Printf("error creating directory %s: %v\n", currentPath, err)
		return
	}

	for _, file := range folder.Files {
		// Join path safely
		filePath := filepath.Join(currentPath, file.Name)
		if err := os.WriteFile(filePath, file.Data, 0644); err != nil {
			fmt.Printf("error writing file %s: %v\n", filePath, err)
		}
	}

	for _, subFolder := range folder.Directories {
		saveFileSystem(subFolder, currentPath)
	}
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
			dir.Directories = append(dir.Directories, subDir.Directories...)
			dir.Files = append(dir.Files, subDir.Files...)
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

// convert file from given path to chunks
// returns hash of the file or big
func fileToHash(path string, chunkToHash map[[32]byte][]byte) ([32]byte, error) {
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		return [32]byte{}, fmt.Errorf("error reading file %s: %v", path, err)
	}

	fmt.Printf("Processing file: %s\n", path)
	fmt.Printf("File content (as bytes): %x\n", fileBytes)
	fmt.Printf("File content (as string): %s", fileBytes)

	chunkList := make([]byte, 0)
	chunkListTmp := make([]byte, 0)

	// empty file case
	if len(fileBytes) == 0 {
		chunk := []byte{byte(Chunk)}
		chunkHash := sha256.Sum256(chunk)
		chunkToHash[chunkHash] = chunk
		fmt.Printf("Empty file hash: %x\n\n", chunkHash)
		return chunkHash, nil
	}

	// Splitting file into chunks of maximal size of 1024 bytes
	for i := 0; i < len(fileBytes); i += 1024 {
		end := min(i+1024, len(fileBytes))
		fileSplit := fileBytes[i:end]
		chunk := append([]byte{byte(Chunk)}, fileSplit...)
		chunkHash := sha256.Sum256(chunk)
		chunkList = append(chunkList, chunkHash[:]...)
		chunkToHash[chunkHash] = chunk
	}

	// If the file is longer then 1024 bytes, we need to use Big type
	// We iterate until we have only one hash left in chunkList that is the
	// final hash of the file
	for len(chunkList) > 32 {

		// We need to fill big with hashes
		for len(chunkList) > 0 {
			end := min(32*32, len(chunkList))

			bigSplit := chunkList[:end]
			chunk := append([]byte{byte(Big)}, bigSplit...)

			chunkHash := sha256.Sum256(chunk)
			chunkListTmp = append(chunkListTmp, chunkHash[:]...)
			chunkToHash[chunkHash] = chunk
			chunkList = chunkList[end:]
		}

		chunkList = append(chunkList, chunkListTmp...)
		chunkListTmp = make([]byte, 0)
	}
	fmt.Printf("File hash: %x\n\n", chunkList[:32])

	return [32]byte(chunkList[:32]), nil
}

// Add directory to Merkle tree
func DirToHash(path string, chunkToHash map[[32]byte][]byte) ([32]byte, error) {
	dirBytes, err := os.ReadDir(path)
	if err != nil {
		return [32]byte{}, fmt.Errorf("error reading directory %s: %v", path, err)
	}

	chunkList := make([]byte, 0)

	// Process each entry in the directory and recursively convert it to hash
	for _, entry := range dirBytes {
		if entry.IsDir() {
			subDirPath := path + "/" + entry.Name()
			subDirHash, err := DirToHash(subDirPath, chunkToHash)
			if err != nil {
				return [32]byte{}, fmt.Errorf("error processing subdirectory %s: %v", subDirPath, err)
			}
			chunkList = append(chunkList, nameToBytes(entry.Name())...)
			chunkList = append(chunkList, subDirHash[:]...)
		} else {
			filePath := path + "/" + entry.Name()
			fileHash, err := fileToHash(filePath, chunkToHash)
			if err != nil {
				return [32]byte{}, fmt.Errorf("error processing file %s: %v", filePath, err)
			}
			chunkList = append(chunkList, nameToBytes(entry.Name())...)
			chunkList = append(chunkList, fileHash[:]...)
		}

	}

	// empty dir case
	if len(chunkList) == 0 {
		chunk := []byte{byte(Directory)}
		chunkHash := sha256.Sum256(chunk)
		chunkToHash[chunkHash] = chunk
		fmt.Printf("Empty directory hash: %x\n\n", chunkHash)
		return chunkHash, nil
	}

	// Splitting directory into groups of maximal size 16 and calculating hash
	chunkListTmp := make([]byte, 0)
	for len(chunkList) > 0 {
		end := min(16*64, len(chunkList))

		dirSplit := chunkList[:end]
		chunk := append([]byte{byte(Directory)}, dirSplit...)
		chunkHash := sha256.Sum256(chunk)

		chunkListTmp = append(chunkListTmp, chunkHash[:]...)
		chunkToHash[chunkHash] = chunk
		chunkList = chunkList[end:]
	}
	chunkList = append(chunkList, chunkListTmp...)
	chunkListTmp = make([]byte, 0)

	// If the directory has more then 16 entries, we need to use Big type
	// We iterate until we have only one hash left in chunkList that is the
	// final hash of the directory
	for len(chunkList) > 32 {

		// We need to fill big with hashes
		for len(chunkList) > 0 {
			end := min(32*32, len(chunkList))
			bigSplit := chunkList[:end]
			chunk := append([]byte{byte(Big)}, bigSplit...)

			chunkHash := sha256.Sum256(chunk)
			chunkListTmp = append(chunkListTmp, chunkHash[:]...)
			chunkToHash[chunkHash] = chunk
			chunkList = chunkList[end:]
		}

		chunkList = append(chunkList, chunkListTmp...)
		chunkListTmp = make([]byte, 0)
	}
	fmt.Printf("Dir hash: %x\n\n", chunkList[:32])

	return [32]byte(chunkList[:32]), nil
}

// Creates a root hash for the file system rooted at a given path and collects
// hashes for Merkle tree construction.
func createFileSystemHash(path string, chunkToHash map[[32]byte][]byte) ([32]byte, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return [32]byte{}, fmt.Errorf("path %s does not exist", path)
	}

	info, err := os.Stat(path)
	if err != nil {
		return [32]byte{}, fmt.Errorf("error getting info for path %s: %v", path, err)
	}
	if info.IsDir() {
		fmt.Printf("[createFileSystemHash] Processing directory: %s\n", path)
		return DirToHash(path, chunkToHash)
	} else {
		fmt.Printf("[createFileSystemHash] Processing file: %s\n", path)
		return fileToHash(path, chunkToHash)
	}
}

func nameToBytes(name string) []byte {
	if len(name) > 32 {
		name = name[:32]
	}
	nameBytes := []byte(name)
	if len(nameBytes) < 32 {
		padding := make([]byte, 32-len(nameBytes))
		nameBytes = append(nameBytes, padding...)
	}
	return nameBytes
}

func printDebugInfo(hash [32]byte, chunkToHash map[[32]byte][]byte, indent string) {
	chunk, exists := chunkToHash[hash]
	if !exists {
		fmt.Printf("Hash %x not found in chunkToHash map\n", hash)
		return
	}

	if chunk[0] == Chunk {
		fmt.Printf("%sChunk found: %x\n", indent, hash)
	} else if chunk[0] == Directory {

		fmt.Printf("%sDirectory found: %x, length: %d [", indent, hash, len(chunk))
		for i := 1; i < len(chunk); i += 64 {
			fmt.Printf(" %s-", string(chunk[i:i+32]))
			fmt.Printf("%x", chunk[i+32:i+64])
		}
		fmt.Printf(" ]\n")

		for i := 1; i < len(chunk); i += 64 {

			data := chunkToHash[[32]byte(chunk[i+32:i+64])]

			if data[0] == Chunk {
				fmt.Printf("%sChunk entry name: %s data: %x, hash: %x\n", indent+"----", chunk[i:i+32], data, chunk[i+32:i+64])
			} else if data[0] == Directory {
				printDebugInfo([32]byte(chunk[i+32:i+64]), chunkToHash, indent+"----")
				// fmt.Printf("%sName %s\n", indent, string(chunk[i:i+32]))
				// fmt.Printf("%sBytes %x\n", indent, chunk[i+32:i+64])
			} else if data[0] == Big {
				printDebugInfo([32]byte(chunk[i+32:i+64]), chunkToHash, indent)
			} else {
				fmt.Printf("%sUnknown entry type: %x, index: %d\n", indent, chunk[i], i)
			}
		}
	} else if chunk[0] == Big {
		fmt.Printf("%sBig entry data: [", indent+"----")

		for i := 1; i < len(chunk); i += 32 {
			fmt.Printf(" %x", chunk[i:i+32])
		}
		fmt.Printf(" ]\n")

		for i := 1; i < len(chunk); i += 32 {
			data := chunkToHash[[32]byte(chunk[i:i+32])]
			if data[0] == Chunk {
				fmt.Printf("%sChunk entry data: %x, hash: %x\n", indent+"----", data, chunk[i:i+32])
			} else if data[0] == Directory {
				printDebugInfo([32]byte(chunk[i:i+32]), chunkToHash, indent+"----")
			} else if data[0] == Big {
				printDebugInfo([32]byte(chunk[i:i+32]), chunkToHash, indent+"----")
			} else {
				fmt.Printf("%sUnknown entry type: %x, index: %d\n", indent+"----", chunk[i], i)
			}
		}
	}
}

// func main() {
// 	if len(os.Args) < 2 {
// 		fmt.Println("Usage: go run main.go <path>")
// 		os.Exit(1)
// 	}

// 	path := os.Args[1]
// 	chunkToHash := make(map[[32]byte][]byte)

// 	hash, err := createFileSystemHash(path, chunkToHash)
// 	if err != nil {
// 		fmt.Printf("Error creating file system hash: %v\n", err)
// 		os.Exit(1)
// 	}
// 	fmt.Printf("File system hash for %s: %x\n", path, hash)

// 	printDebugInfo(hash, chunkToHash, "")
// }
