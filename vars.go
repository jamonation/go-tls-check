package tlschk

import (
	"github.com/fatih/color"
)

var (
	//Label prints with nice formatting
	Label = color.New(color.FgRed, color.Bold).SprintFunc()
	//Warning tries to really stand out with extra underline
	Warning = color.New(color.FgRed, color.Bold, color.Underline)
)
