"use client"
//the library handles light and dark theme ,remembering the choice and following the system theme
import * as React from "react"
import { ThemeProvider as NextThemesProvider } from "next-themes"

type ThemeProviderProps =
    React.ComponentProps<typeof NextThemesProvider>

export function ThemeProvider({
    children,
    ...props
}: ThemeProviderProps) {
    return (
        <NextThemesProvider {...props}>
            {children}
        </NextThemesProvider>
    )
}