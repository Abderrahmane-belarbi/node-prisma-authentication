import { prisma } from "../src/lib/prisma";

async function seed() {
  const createdUsers = await prisma.user.createMany({
    data: Array.from({ length: 20 }, (_, i) => ({
      name: `User ${i + 1}`,
      email: `user${i + 1}@gmail.com`,
      passwordHash: `hashed_password${i + 1}`,
    })),
  })
}

seed()
  .catch(console.error)
  .finally(async () => {
    await prisma.$disconnect();
  });