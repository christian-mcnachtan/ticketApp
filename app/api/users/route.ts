import prisma from "@/prisma/db";
import { userSchema } from "@/ValidationSchemas/user";
import { NextRequest, NextResponse } from "next/server";
import bcrypt from 'bcryptjs';
import { getServerSession } from "next-auth";
import options from "../auth/[...nextauth]/options";

export async function POST(request: NextRequest): Promise<NextResponse> {
    // Get the session
    const session = await getServerSession(options);

    // If no session, return unauthorized error
    if (!session) {
        return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    // Check if the user is an admin
    if (session.user.role !== "ADMIN") {
        return NextResponse.json({ error: "Not Authorized" }, { status: 403 });
    }

    // Parse and validate the request body using Zod schema
    const body = await request.json();
    const validation = userSchema.safeParse(body);

    // If validation fails, return validation errors
    if (!validation.success) {
        return NextResponse.json(validation.error.format(), { status: 400 });
    }

    // Check for duplicate username
    const duplicate = await prisma.user.findUnique({ where: { username: body.username } });
    if (duplicate) {
        return NextResponse.json({ message: "Duplicate Username" }, { status: 409 });
    }

    // Hash the password and create the new user
    const hashPassword = await bcrypt.hash(body.password, 10);
    body.password = hashPassword;

    // Create new user in the database
    const newUser = await prisma.user.create({ data: { ...body } });

    // Return the newly created user
    return NextResponse.json(newUser, { status: 201 });
}
